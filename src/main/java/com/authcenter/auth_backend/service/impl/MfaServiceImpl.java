package com.authcenter.auth_backend.service.impl;

import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.repository.UserRepository;
import com.authcenter.auth_backend.service.MfaService;
import org.apache.commons.codec.binary.Base32;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Random;

@Service
public class MfaServiceImpl implements MfaService {
	private final UserRepository userRepository;

	public MfaServiceImpl(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
	public String generateSecretForUser(User user) {
		byte[] rnd = new byte[20];
		new Random().nextBytes(rnd);
		String base32 = new Base32().encodeToString(rnd).replace("=", "");
		user.setMfaSecret(base32);
		user.setMfaEnabled(false);
		userRepository.save(user);
		return base32;
	}

	@Override
	public String buildOtpAuth(User user, String issuer) {
		String label = URLEncoder.encode("AuthCenter:" + user.getEmail(), StandardCharsets.UTF_8);
		String iss = URLEncoder.encode(issuer, StandardCharsets.UTF_8);
		return "otpauth://totp/" + label + "?secret=" + user.getMfaSecret() + "&issuer=" + iss + "&digits=6&period=30";
	}

	@Override
	public boolean verify(User user, int code) {
		if (user.getMfaSecret() == null) return false;
		long ts = Instant.now().getEpochSecond() / 30;
		for (long i = -1; i <= 1; i++) {
			if (totp(user.getMfaSecret(), ts + i) == code) return true;
		}
		return false;
	}

	private int totp(String base32Secret, long timestep) {
		byte[] key = new Base32().decode(base32Secret);
		byte[] data = ByteBuffer.allocate(8).putLong(timestep).array();
		try {
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(new SecretKeySpec(key, "HmacSHA1"));
			byte[] hash = mac.doFinal(data);
			int offset = hash[hash.length - 1] & 0x0F;
			int binary = ((hash[offset] & 0x7F) << 24)
					| ((hash[offset + 1] & 0xFF) << 16)
					| ((hash[offset + 2] & 0xFF) << 8)
					| (hash[offset + 3] & 0xFF);
			return binary % 1_000_000;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
