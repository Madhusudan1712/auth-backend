package com.authcenter.auth_backend.service;

import com.authcenter.auth_backend.model.RefreshToken;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenService {
    RefreshToken save(String token, UUID userId, long jwtRefreshExpirationMs);
    Optional<RefreshToken> findByToken(String token);
    void delete(RefreshToken refreshToken);
    void deleteByUserId(UUID userId);
    boolean isExpired(RefreshToken refreshToken);
}
