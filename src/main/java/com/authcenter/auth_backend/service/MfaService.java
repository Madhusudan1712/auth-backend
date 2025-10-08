package com.authcenter.auth_backend.service;

import com.authcenter.auth_backend.model.User;

public interface MfaService {
    String generateSecretForUser(User user);
    String buildOtpAuth(User user, String issuer);
    boolean verify(User user, int code);
}
