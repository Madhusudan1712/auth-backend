package com.authcenter.auth_backend.service.impl;

import com.authcenter.auth_backend.model.RefreshToken;
import com.authcenter.auth_backend.repository.RefreshTokenRepository;
import com.authcenter.auth_backend.service.RefreshTokenService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenServiceImpl implements RefreshTokenService {

	private final RefreshTokenRepository refreshTokenRepository;

	public RefreshTokenServiceImpl(RefreshTokenRepository refreshTokenRepository) {
		this.refreshTokenRepository = refreshTokenRepository;
	}

	@Override
	@Transactional
	public RefreshToken save(String token, UUID userId, long jwtRefreshExpirationMs) {
		RefreshToken refreshToken = new RefreshToken();
		refreshToken.setToken(token);
		refreshToken.setUserId(userId);
		refreshToken.setExpiryDate(Instant.now().plusMillis(jwtRefreshExpirationMs));
		return refreshTokenRepository.save(refreshToken);
	}

	@Override
	public Optional<RefreshToken> findByToken(String token) {
		return refreshTokenRepository.findByToken(token);
	}

	@Override
	@Transactional
	public void delete(RefreshToken refreshToken) {
		refreshTokenRepository.delete(refreshToken);
	}

	@Override
	@Transactional
	public void deleteByUserId(UUID userId) {
		refreshTokenRepository.deleteAllByUserId(userId);
	}

	@Override
	public boolean isExpired(RefreshToken refreshToken) {
		return refreshToken.getExpiryDate().isBefore(Instant.now());
	}
}
