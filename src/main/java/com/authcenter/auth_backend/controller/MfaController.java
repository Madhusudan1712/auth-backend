package com.authcenter.auth_backend.controller;

import com.authcenter.auth_backend.dto.response.ApiResponse;
import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.repository.UserRepository;
import com.authcenter.auth_backend.service.MfaService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/auth")
public class MfaController {

    private final MfaService mfaService;
    private final UserRepository userRepository;

    public MfaController(MfaService mfaService, UserRepository userRepository) {
        this.mfaService = mfaService;
        this.userRepository = userRepository;
    }

    @PostMapping("/setup-mfa")
    public ResponseEntity<?> setupMfa(@RequestParam("email") String email) {
        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isEmpty()) {
            return ResponseEntity.badRequest().body(new ApiResponse<>("User not found", null, 400));
        }

        User user = userOpt.get();
        String secret = mfaService.generateSecretForUser(user);

        // Format for Google Authenticator
        String otpAuthUrl = String.format(
                "otpauth://totp/AuthCenter:%s?secret=%s&issuer=AuthCenter",
                user.getEmail(), secret
        );

        return ResponseEntity.ok(new ApiResponse<>("MFA Secret generated", otpAuthUrl, 200));
    }

    @PostMapping("/verify-mfa")
    public ResponseEntity<?> verifyMfa(@RequestParam("userId") UUID userId,
                                       @RequestParam("otp") int otp) {
        boolean isValid = mfaService.verifyMfaCode(userId, otp);
        if (!isValid) {
            return ResponseEntity.status(403).body(new ApiResponse<>("Invalid MFA code", null, 403));
        }
        return ResponseEntity.ok(new ApiResponse<>("MFA verification successful", null, 200));
    }
}
