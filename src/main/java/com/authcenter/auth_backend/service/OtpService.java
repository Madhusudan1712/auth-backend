package com.authcenter.auth_backend.service;

import com.authcenter.auth_backend.dto.request.OtpRequest;
import com.authcenter.auth_backend.exception.OtpException;
import com.authcenter.auth_backend.model.OtpToken;

import java.io.UnsupportedEncodingException;
import java.util.Random;
import com.authcenter.auth_backend.model.OtpPurpose;
import com.authcenter.auth_backend.repository.OtpTokenRepository;
import jakarta.mail.MessagingException;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.binary.Hex;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.apache.commons.codec.DecoderException;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import com.authcenter.auth_backend.utils.UrlUtils;

/**
 * Service for handling OTP (One-Time Password) generation, validation, and consumption.
 */
@Service
@Transactional
public class OtpService {
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

    public OtpService(OtpTokenRepository otpTokenRepository, EmailService emailService) {
        this.otpTokenRepository = otpTokenRepository;
        this.emailService = emailService;
    }

    /**
     * Generates and sends an OTP to the user's email.
     *
     * @param otpRequest the OTP request containing the user's email, application, and OTP purpose
     * @return the session ID for the generated OTP
     */
    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(OtpService.class);

    public String generateAndSendOtp(OtpRequest otpRequest) {
        String email = otpRequest.getEmail().toLowerCase();
        String application = UrlUtils.extractHost(otpRequest.getApplication());
        OtpPurpose otpPurpose = otpRequest.getOtpPurpose();
        
        logger.info("Generating OTP for email: {}, application: {}, purpose: {}", email, application, otpPurpose);

        // Check if there's an existing OTP and if rate limit applies
        Optional<OtpToken> existingTokenOpt = otpTokenRepository
                .findByEmailAndApplicationAndOtpPurpose(email, application, otpPurpose);

        if (existingTokenOpt.isPresent()) {
            OtpToken existingToken = existingTokenOpt.get();
            if (!existingToken.canResend()) {
                long secondsLeft = Duration.between(
                    LocalDateTime.now(),
                    existingToken.getUpdated().plusMinutes(rateLimitMinutes)
                ).getSeconds();
                throw new OtpException("Please wait " + secondsLeft + " seconds before requesting a new OTP", 
                                   HttpStatus.TOO_MANY_REQUESTS);
            }
            // Update existing OTP token with new values
            String otp = generateNumericOtp(otpLength);
            String salt = generateSalt();
            
            existingToken.setHashedOtp(hashOtp(otp, salt));
            existingToken.setSalt(salt);
            existingToken.setExpiresAt(LocalDateTime.now().plusMinutes(otpExpiryMinutes));
            existingToken.setUsed(false);
            existingToken.setAttempts(0);
            existingToken.setUpdated(LocalDateTime.now());
            
            // Send the OTP email
            logger.debug("Sending OTP email to: {}", email);
            try {
                emailService.sendOtpEmail(email, otp, otpPurpose, application);
                logger.info("OTP email sent successfully to: {}", email);
            } catch (MessagingException e) {
                logger.error("Failed to send OTP email to {}: {}", email, e.getMessage(), e);
                throw new OtpException("Failed to send OTP email. Please try again later.", e);
            } catch (UnsupportedEncodingException e) {
                logger.error("Encoding error when sending OTP email to {}: {}", email, e.getMessage(), e);
                throw new OtpException("System error when sending OTP. Please contact support.", e);
            }
            
            // Save the updated token and return the existing session ID
            otpTokenRepository.save(existingToken);
            return existingToken.getSessionId();
        }

        // Generate new OTP, salt, and session for new token
        String otp = generateNumericOtp(otpLength);
        String sessionId = UUID.randomUUID().toString();
        String salt = generateSalt();
        String hashedOtp = hashOtp(otp, salt);

        // Create and save new OTP token
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
            logger.info("OTP email sent successfully to: {}", email);
            return sessionId;
        } catch (Exception e) {
            logger.error("Failed to send OTP email to: " + email, e);
            // Clean up the OTP token since email sending failed
            otpTokenRepository.delete(otpToken);
            throw new OtpException("Failed to send OTP email: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Validates and consumes an OTP.
     *
     * @param sessionId the session ID for the OTP
     * @param email the user's email
     * @param otp the OTP to validate
     * @param purpose the OTP purpose
     * @return true if the OTP is valid, false otherwise
     */
    public boolean validateAndConsumeOtp(String sessionId, String email, String otp, OtpPurpose purpose) {
        OtpToken token = otpTokenRepository.findBySessionIdAndEmailAndOtpPurpose(sessionId, email, purpose)
                .orElseThrow(() -> new OtpException("Invalid OTP session", HttpStatus.BAD_REQUEST));

        // Check if OTP is already used
        if (token.isUsed()) {
            throw new OtpException("OTP has already been used", HttpStatus.BAD_REQUEST);
        }

        // Check if OTP is expired
        if (token.isExpired()) {
            throw new OtpException("OTP has expired", HttpStatus.BAD_REQUEST);
        }

        // Check max attempts
        if (token.getAttempts() >= maxAttempts) {
            throw new OtpException("Maximum number of attempts reached. Please request a new OTP.", 
                                 HttpStatus.TOO_MANY_REQUESTS);
        }

        // Verify OTP with salt
        if (!verifyOtp(otp, token.getHashedOtp(), token.getSalt())) {
            token.incrementAttempts();
            otpTokenRepository.save(token);
            
            int attemptsLeft = maxAttempts - token.getAttempts();
            throw new OtpException("Invalid OTP. Attempts left: " + attemptsLeft, 
                                 HttpStatus.BAD_REQUEST);
        }

        // Mark OTP as used
        token.setUsed(true);
        otpTokenRepository.save(token);
        return true;
    }

    /**
     * Cleans up expired OTPs.
     */
    @Scheduled(fixedRate = 3600000) // 1 hour in milliseconds
    public void cleanupExpiredOtps() {
        otpTokenRepository.deleteByExpiresAtBeforeOrUsedTrue(LocalDateTime.now().minusDays(1));
    }

    /**
     * Generates a numeric OTP. 
     * @param length the length of the OTP
     * @return a numeric OTP with the specified length
     */
    private String generateNumericOtp(int length) {
        // Generate a numeric OTP with specified length
        int min = (int) Math.pow(10, length - 1);
        int max = (int) Math.pow(10, length) - 1;
        return String.format("%0" + length + "d", new Random().nextInt(max - min + 1) + min);
    }

    /**
     * Hashes an OTP using a secret key.
     *
     * @param otp the OTP to hash
     * @return the hashed OTP
     */
    /**
     * Generates a cryptographically secure random salt.
     * @return a hex-encoded salt string
     */
    private String generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        return Hex.encodeHexString(salt);
    }

    /**
     * Hashes an OTP with a salt using PBKDF2 with HMAC-SHA256.
     *
     * @param otp the OTP to hash
     * @param salt the salt to use for hashing
     * @return the hashed OTP
     */
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

    /**
     * Verifies an OTP by comparing it with the stored hash using the stored salt.
     *
     * @param inputOtp the OTP to verify
     * @param storedHash the stored hash of the OTP
     * @param salt the salt used for the original hash
     * @return true if the OTP is valid, false otherwise
     */
    private boolean verifyOtp(String inputOtp, String storedHash, String salt) {
        if (inputOtp == null || storedHash == null || salt == null) {
            return false;
        }
        String inputHash = hashOtp(inputOtp, salt);
        return inputHash.equals(storedHash);
    }
}