package com.authcenter.auth_backend.service;

import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.repository.UserRepository;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
public class MfaService {

    private final UserRepository userRepository;
    private final GoogleAuthenticator gAuth;

    public MfaService(UserRepository userRepository) {
        this.userRepository = userRepository;
        this.gAuth = new GoogleAuthenticator();
    }

    public String generateSecretForUser(User user) {
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        String secret = key.getKey();

        user.setMfaSecret(secret);
        user.setMfaEnabled(true);
        userRepository.save(user);

        return secret;
    }

    public boolean verifyMfaCode(UUID userId, int code) {
        Optional<User> userOpt = userRepository.findById(userId);
        if (userOpt.isEmpty()) return false;

        User user = userOpt.get();
        if (!user.isMfaEnabled() || user.getMfaSecret() == null) return false;

        return gAuth.authorize(user.getMfaSecret(), code);
    }
}
