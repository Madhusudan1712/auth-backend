package com.authcenter.auth_backend.controller;

import com.authcenter.auth_backend.dto.response.ApiResponse;
import com.authcenter.auth_backend.model.Role;
import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.model.UserRole;
import com.authcenter.auth_backend.repository.UserRepository;
import com.authcenter.auth_backend.security.JwtService;
import com.authcenter.auth_backend.service.EmailService;
import com.authcenter.auth_backend.service.MfaService;
import com.authcenter.auth_backend.service.OtpService;
import com.authcenter.auth_backend.utils.CookieUtil;
import com.authcenter.auth_backend.utils.UrlUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

@RestController
@RequestMapping("/auth/mfa")
public class MfaController {
    private final MfaService mfaService;
    private final UserRepository userRepository;
    private final OtpService otpService;
    private final EmailService emailService;
    private final JwtService jwtService;

    @Value("${jwt.access.expiration.ms:900000}")
    private long jwtAccessExpirationMs;

    @Value("${jwt.refresh.expiration.ms:604800000}")
    private long jwtRefreshExpirationMs;

    @Value("${authcenter.redirect.allowed-uris}")
    private String[] allowedRedirectOrigins;

    public MfaController(MfaService mfaService, UserRepository userRepository,
                         OtpService otpService, EmailService emailService, JwtService jwtService) {
        this.mfaService = mfaService;
        this.userRepository = userRepository;
        this.otpService = otpService;
        this.emailService = emailService;
        this.jwtService = jwtService;
    }

    /** UI entry (after login) if mfa required */
    @GetMapping("/verify-page")
    public void verifyPage(@RequestParam String redirect, HttpServletResponse resp) throws Exception {
        resp.setStatus(303);
        // push the SPA MFA page (authcenter UI) with the app redirect attached
        resp.setHeader("Location", "http://authcenter.madhusudan.space:5000/mfa?redirect=" +
                URLEncoder.encode(redirect==null?"":redirect, StandardCharsets.UTF_8));
    }

    @PostMapping("/setup")
    public ResponseEntity<?> setup(@RequestParam UUID userId) {
        Optional<User> u = userRepository.findById(userId);
        if (u.isEmpty()) {
            return ResponseEntity.badRequest().body(new ApiResponse<>("User not found", null, 400));
        }

        User user = u.get();
        if (user.isMfaEnabled()) {
            // MFA already set up → skip QR
            return ResponseEntity.ok(new ApiResponse<>("MFA already enabled", Map.of("mfaAlreadyEnabled", true), 200));
        }

        String secret = mfaService.generateSecretForUser(user);
        String url = mfaService.buildOtpAuth(user, "AuthCenter");
        return ResponseEntity.ok(new ApiResponse<>("MFA Secret generated", url, 200));
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verify(
            @RequestParam UUID userId,
            @RequestParam int otp,
            @RequestParam String redirect,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        Optional<User> u = userRepository.findById(userId);
        if (u.isEmpty()) {
            return ResponseEntity.badRequest().body(new ApiResponse<>("User not found", null, 400));
        }

        User user = u.get();

        //Verify OTP
        boolean ok = mfaService.verify(user, otp);
        if (!ok) {
            return ResponseEntity.status(403).body(new ApiResponse<>("Invalid MFA code", null, 403));
        }

        //Enable MFA if first-time setup
        if (!user.isMfaEnabled()) {
            user.setMfaEnabled(true);
            userRepository.save(user);
        }

        //Validate redirect BEFORE generating tokens/cookies
    try {
        URI uri = new URI(redirect);
        String host = uri.getHost();
        int port = uri.getPort();
        String scheme = uri.getScheme();

        boolean isAllowed = Arrays.stream(allowedRedirectOrigins)
            .map(String::trim)
            .anyMatch(allowed -> {
            try {
                URI allowedUri = new URI(allowed);
                String allowedHost = allowedUri.getHost();
                return host != null
                    && allowedHost != null
                    && (host.equalsIgnoreCase(allowedHost) || host.endsWith("." + allowedHost))
                    && allowedUri.getScheme().equalsIgnoreCase(scheme)
                    && (allowedUri.getPort() == -1 || allowedUri.getPort() == port);
            } catch (Exception e) {
                return false;
            }
            });

        if (!isAllowed) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(new ApiResponse<>("Redirect URI not allowed", null, 403));
        }

        // Only here we generate tokens and set cookies
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", user.getId().toString());
        claims.put("name", user.getName());
        claims.put("email", user.getEmail());
        claims.put("roles", user.getRoles()
            .stream()
            .map(UserRole::getRole)
            .map(Role::name)
            .toList());
        claims.put("application", user.getApplication());

        String accessToken = jwtService.generateAccessToken(claims, user.getEmail(), jwtAccessExpirationMs);
        String refreshToken = jwtService.generateRefreshToken(user.getEmail(), jwtRefreshExpirationMs);

        // Set cookie domain to relying app's subdomain
        String cookieDomain = UrlUtils.extractHost(redirect);
        CookieUtil.addAuthCookies(request, response, accessToken, refreshToken, jwtAccessExpirationMs, jwtRefreshExpirationMs, cookieDomain);

        return ResponseEntity.ok(
            new ApiResponse<>(
                "MFA verification successful",
                Map.of("redirect", redirect),
                200
            )
        );

    } catch (Exception e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(new ApiResponse<>("Invalid redirect URI format", null, 400));
    }
    }

    @PostMapping("/skip")
    public ResponseEntity<?> skip(
            @RequestParam UUID userId,
            @RequestParam String redirect,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        Optional<User> u = userRepository.findById(userId);
        if (u.isEmpty()) {
            return ResponseEntity.badRequest().body(new ApiResponse<>("User not found", null, 400));
        }

        User user = u.get();

        // If MFA already enabled, skipping is not allowed
        if (user.isMfaEnabled()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>("MFA already enabled. Cannot skip setup.", null, 403));
        }

    try {
        URI uri = new URI(redirect);
        String host = uri.getHost();
        int port = uri.getPort();
        String scheme = uri.getScheme();

        boolean isAllowed = Arrays.stream(allowedRedirectOrigins)
            .map(String::trim)
            .anyMatch(allowed -> {
            try {
                URI allowedUri = new URI(allowed);
                return allowedUri.getHost() != null
                    && host != null
                    && host.equalsIgnoreCase(allowedUri.getHost())
                    && allowedUri.getScheme().equalsIgnoreCase(scheme)
                    && (allowedUri.getPort() == -1 || allowedUri.getPort() == port);
            } catch (Exception e) {
                return false;
            }
            });

        if (!isAllowed) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(new ApiResponse<>("Redirect URI not allowed", null, 403));
        }

        // Only here: generate JWT + set cookies
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", user.getId().toString());
        claims.put("name", user.getName());
        claims.put("email", user.getEmail());
        claims.put("roles", user.getRoles()
            .stream()
            .map(UserRole::getRole)
            .map(Role::name)
            .toList());
        claims.put("application", user.getApplication());

        String accessToken = jwtService.generateAccessToken(claims, user.getEmail(), jwtAccessExpirationMs);
        String refreshToken = jwtService.generateRefreshToken(user.getEmail(), jwtRefreshExpirationMs);

        // Set cookie domain to relying app's subdomain
        String cookieDomain = UrlUtils.extractHost(redirect);
        CookieUtil.addAuthCookies(request, response, accessToken, refreshToken, jwtAccessExpirationMs, jwtRefreshExpirationMs, cookieDomain);

        return ResponseEntity.ok(
            new ApiResponse<>(
                "MFA skipped successfully",
                Map.of("redirect", redirect),
                200
            )
        );

    } catch (Exception e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(new ApiResponse<>("Invalid redirect URI format", null, 400));
    }
    }

    @PostMapping("/request-disable")
    public ResponseEntity<?> requestDisable(@RequestParam String email) {
        String otp = otpService.issue(email, 10);
        String otpRequiredFor = "Disable mfa setup";
        emailService.sendOtpEmail(email, otp, otpRequiredFor); // simple plaintext email
        return ResponseEntity.ok(new ApiResponse<>("OTP sent to email", null, 200));
    }

    @PostMapping("/confirm-disable")
    public ResponseEntity<?> confirmDisable(@RequestParam String email, @RequestParam String otp) {
        if (!otpService.consume(email, otp)) {
            return ResponseEntity.status(403).body(new ApiResponse<>("Invalid or expired OTP", null, 403));
        }
        Optional<User> u = userRepository.findByEmail(email);
        if (u.isEmpty()) return ResponseEntity.status(404).body(new ApiResponse<>("User not found", null, 404));
        User user = u.get();
        user.setMfaEnabled(false);
        user.setMfaSecret(null);
        userRepository.save(user);
        return ResponseEntity.ok(new ApiResponse<>("MFA disabled", null, 200));
    }
}
