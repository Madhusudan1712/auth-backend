package com.authcenter.auth_backend.service;

import com.authcenter.auth_backend.model.RefreshToken;
import com.authcenter.auth_backend.repository.RefreshTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Transactional
    public RefreshToken save(String token, UUID userId, long jwtRefreshExpirationMs) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(token);
        refreshToken.setUserId(userId);
        refreshToken.setExpiryDate(Instant.now().plusMillis(jwtRefreshExpirationMs));

        return refreshTokenRepository.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public void delete(RefreshToken refreshToken) {
        refreshTokenRepository.delete(refreshToken);
    }

    @Transactional
    public void deleteByUserId(UUID userId) {
        refreshTokenRepository.deleteAllByUserId(userId);
    }

    public boolean isExpired(RefreshToken refreshToken) {
        return refreshToken.getExpiryDate().isBefore(Instant.now());
    }
}
