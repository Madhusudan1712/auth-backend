package com.authcenter.auth_backend.service.impl;

import com.authcenter.auth_backend.dto.request.OtpRequest;
import com.authcenter.auth_backend.exception.OtpException;
import com.authcenter.auth_backend.model.OtpPurpose;
import com.authcenter.auth_backend.model.OtpToken;
import com.authcenter.auth_backend.repository.OtpTokenRepository;
import com.authcenter.auth_backend.service.EmailService;
import com.authcenter.auth_backend.service.OtpService;
import com.authcenter.auth_backend.utils.UrlUtils;
import jakarta.mail.MessagingException;
import org.apache.commons.codec.binary.Hex;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;

@Service
@Transactional
public class OtpServiceImpl implements OtpService {
	private static final int SALT_LENGTH = 32; // 256 bits
	private static final int HASH_ITERATIONS = 10000;
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	@Value("${authcenter.otp.length:6}")
	private int otpLength;

	@Value("${authcenter.otp.max.attempts:5}")
	private int maxAttempts;

	@Value("${authcenter.otp.expiration.minutes:5}")
	private int otpExpiryMinutes;

	@Value("${authcenter.otp.rate.limit.minutes:1}")
	private int rateLimitMinutes;

	private final OtpTokenRepository otpTokenRepository;
	private final EmailService emailService;

	public OtpServiceImpl(OtpTokenRepository otpTokenRepository, EmailService emailService) {
		this.otpTokenRepository = otpTokenRepository;
		this.emailService = emailService;
	}

	private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(OtpServiceImpl.class);

	@Override
	public String generateAndSendOtp(OtpRequest otpRequest) {
		String email = otpRequest.getEmail().toLowerCase();
		String application = UrlUtils.extractHost(otpRequest.getApplication());
		OtpPurpose otpPurpose = otpRequest.getOtpPurpose();

		logger.info("Generating OTP for email: {}, application: {}, purpose: {}", email, application, otpPurpose);

		Optional<OtpToken> existingTokenOpt = otpTokenRepository
				.findByEmailAndApplicationAndOtpPurpose(email, application, otpPurpose);

		if (existingTokenOpt.isPresent()) {
			OtpToken existingToken = existingTokenOpt.get();
			if (!existingToken.canResend()) {
				long secondsLeft = Duration.between(
						LocalDateTime.now(),
						existingToken.getUpdated().plusMinutes(rateLimitMinutes)
				).getSeconds();
				throw new OtpException("Please wait " + secondsLeft + " seconds before requesting a new OTP", HttpStatus.TOO_MANY_REQUESTS);
			}
			String otp = generateNumericOtp(otpLength);
			String salt = generateSalt();

			existingToken.setHashedOtp(hashOtp(otp, salt));
			existingToken.setSalt(salt);
			existingToken.setExpiresAt(LocalDateTime.now().plusMinutes(otpExpiryMinutes));
			existingToken.setUsed(false);
			existingToken.setAttempts(0);
			existingToken.setUpdated(LocalDateTime.now());

			logger.debug("Sending OTP email to: {}", email);
			try {
				emailService.sendOtpEmail(email, otp, otpPurpose, application);
				logger.info("OTP email sent successfully for existing user, to: {}", email);
			} catch (MessagingException e) {
				logger.error("Failed to send OTP email to {}: {}", email, e.getMessage(), e);
				throw new OtpException("Failed to send OTP email. Please try again later.", e);
			} catch (UnsupportedEncodingException e) {
				logger.error("Encoding error when sending OTP email to {}: {}", email, e.getMessage(), e);
				throw new OtpException("System error when sending OTP. Please contact support.", e);
			}

			otpTokenRepository.save(existingToken);
			return existingToken.getSessionId();
		}

		String otp = generateNumericOtp(otpLength);
		String sessionId = UUID.randomUUID().toString();
		String salt = generateSalt();
		String hashedOtp = hashOtp(otp, salt);

		OtpToken otpToken = new OtpToken();
		otpToken.setEmail(email);
		otpToken.setApplication(application);
		otpToken.setOtpPurpose(otpPurpose);
		otpToken.setHashedOtp(hashedOtp);
		otpToken.setSessionId(sessionId);
		otpToken.setSalt(salt);
		otpToken.setExpiresAt(LocalDateTime.now().plusMinutes(otpExpiryMinutes));
		otpToken.setUsed(false);

		otpTokenRepository.save(otpToken);

		try {
			logger.debug("Sending OTP email to: {}", email);
			emailService.sendOtpEmail(email, otp, otpPurpose, application);
			logger.info("OTP email sent successfully for new user, to: {}", email);
			return sessionId;
		} catch (Exception e) {
			logger.error("Failed to send OTP email to: {}", email, e);
			otpTokenRepository.delete(otpToken);
			throw new OtpException("Failed to send OTP email: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	@Override
	public boolean validateAndConsumeOtp(String sessionId, String email, String otp, OtpPurpose purpose) {
		OtpToken token = otpTokenRepository.findBySessionIdAndEmailAndOtpPurpose(sessionId, email, purpose)
				.orElseThrow(() -> new OtpException("Invalid OTP session", HttpStatus.BAD_REQUEST));

		if (token.isUsed()) {
			throw new OtpException("OTP has already been used", HttpStatus.BAD_REQUEST);
		}

		if (token.isExpired()) {
			throw new OtpException("OTP has expired", HttpStatus.BAD_REQUEST);
		}

		if (token.getAttempts() >= maxAttempts) {
			throw new OtpException("Maximum number of attempts reached. Please request a new OTP.", HttpStatus.TOO_MANY_REQUESTS);
		}

		if (!verifyOtp(otp, token.getHashedOtp(), token.getSalt())) {
			token.incrementAttempts();
			otpTokenRepository.save(token);

			int attemptsLeft = maxAttempts - token.getAttempts();
			throw new OtpException("Invalid OTP. Attempts left: " + attemptsLeft, HttpStatus.BAD_REQUEST);
		}

		token.setUsed(true);
		otpTokenRepository.save(token);
		return true;
	}

	@Override
	@Scheduled(fixedRate = 3600000)
	public void cleanupExpiredOtps() {
		otpTokenRepository.deleteByExpiresAtBeforeOrUsedTrue(LocalDateTime.now().minusDays(1));
	}

	private String generateNumericOtp(int length) {
		int min = (int) Math.pow(10, length - 1);
		int max = (int) Math.pow(10, length) - 1;
		return String.format("%0" + length + "d", new Random().nextInt(max - min + 1) + min);
	}

	private String generateSalt() {
		byte[] salt = new byte[SALT_LENGTH];
		SECURE_RANDOM.nextBytes(salt);
		return Hex.encodeHexString(salt);
	}

	private String hashOtp(String otp, String salt) {
		try {
			byte[] saltBytes = Hex.decodeHex(salt);
			PBEKeySpec spec = new PBEKeySpec(
					otp.toCharArray(),
					saltBytes,
					HASH_ITERATIONS,
					256
			);
			SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			byte[] hash = skf.generateSecret(spec).getEncoded();
			return Hex.encodeHexString(hash);
		} catch (Exception e) {
			throw new RuntimeException("Error hashing OTP", e);
		}
	}

	private boolean verifyOtp(String inputOtp, String storedHash, String salt) {
		if (inputOtp == null || storedHash == null || salt == null) {
			return false;
		}
		String inputHash = hashOtp(inputOtp, salt);
		return inputHash.equals(storedHash);
	}
}
