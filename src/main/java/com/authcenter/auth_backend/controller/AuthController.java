package com.authcenter.auth_backend.controller;

import com.authcenter.auth_backend.dto.request.*;
import com.authcenter.auth_backend.dto.response.ApiResponse;
import com.authcenter.auth_backend.model.Role;
import com.authcenter.auth_backend.model.Status;
import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.model.UserRole;
import com.authcenter.auth_backend.security.JwtService;
import com.authcenter.auth_backend.service.*;
import com.authcenter.auth_backend.utils.StringGenerator;
import com.authcenter.auth_backend.utils.CookieUtil;
import com.authcenter.auth_backend.utils.UrlUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final OtpService otpService;
    private final RecaptchaService recaptchaService;
    private final EmailService emailService;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    @Value("${jwt.access.expiration.ms:900000}")
    private long jwtAccessExpirationMs;

    @Value("${jwt.refresh.expiration.ms:604800000}")
    private long jwtRefreshExpirationMs;

    @Value("${authcenter.cors.allowed-origins}")
    private String[] allowedRedirectOrigins;

    @Value("${authcenter.super.admin.email}")
    private String superAdminEmail;

    public AuthController(
            UserService userService,
            OtpService otpService,
            RecaptchaService recaptchaService,
            EmailService emailService,
            JwtService jwtService,
            PasswordEncoder passwordEncoder
    ) {
        this.userService = userService;
        this.otpService = otpService;
        this.recaptchaService = recaptchaService;
        this.emailService = emailService;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/recaptcha/verify")
    public ResponseEntity<?> verifyCaptcha(@RequestBody RecaptchaRequest request) {
        boolean valid = recaptchaService.isCaptchaValid(request.getToken());
        return ResponseEntity.ok(new ApiResponse<>("CAPTCHA validation result", valid, 200));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return ResponseEntity.status(401).body(new ApiResponse<>("No refresh token found", null, 401));
        }

        Optional<String> refreshTokenOpt = Arrays.stream(cookies)
                .filter(c -> "refresh_token".equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst();

        if (refreshTokenOpt.isEmpty()) {
            return ResponseEntity.status(401).body(new ApiResponse<>("Missing refresh token", null, 401));
        }

        String refreshToken = refreshTokenOpt.get();
        if (!jwtService.validateToken(refreshToken) || jwtService.isTokenExpired(refreshToken)) {
            return ResponseEntity.status(401).body(new ApiResponse<>("Invalid or expired refresh token", null, 401));
        }

        String email = jwtService.extractEmail(refreshToken);
        Optional<User> userOpt = userService.findByEmail(email);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(404).body(new ApiResponse<>("User not found", null, 404));
        }

        User user = userOpt.get();
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

        String newAccessToken = jwtService.generateAccessToken(claims, email, jwtAccessExpirationMs);

        Cookie accessCookie = new Cookie("auth_token", newAccessToken);
        accessCookie.setHttpOnly(true);
        accessCookie.setSecure(false);
        accessCookie.setPath("/");
        accessCookie.setMaxAge((int) Duration.ofMillis(jwtAccessExpirationMs).getSeconds());
        response.addCookie(accessCookie);

        String requestDomain = request.getServerName();

        if (!requestDomain.equalsIgnoreCase("localhost") && requestDomain.endsWith("madhusudan.space")) {
            accessCookie.setDomain(".madhusudan.space");
        }

        return ResponseEntity.ok(new ApiResponse<>("Access token refreshed", Map.of("accessToken", newAccessToken), 200));
    }

    @GetMapping("/roles")
    public ApiResponse<List<Map<String, String>>> getRoles() {
        List<Map<String, String>> roles = Arrays.stream(Role.values())
                .map(role -> Map.of("name", role.name(), "label", role.getDisplayName()))
                .collect(Collectors.toList());

        return new ApiResponse<>("Roles fetched successfully", roles, 200);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @Valid @RequestBody LoginRequest req,
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {

        if (!recaptchaService.isCaptchaValid(req.getCaptchaToken())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>("Invalid CAPTCHA", null, 403));
        }

    String redirectHost = UrlUtils.extractHost(req.getRedirect());
    Optional<User> userOpt = userService.findByEmailAndApplication(req.getEmail(), redirectHost);

        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>("User not found", null, 404));
        }

        User user = userOpt.get();
        if (userOpt.isEmpty() || !passwordEncoder.matches(req.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>("Invalid email or password", null, 401));
        }

    // If MFA is NOT enabled → setup page
    if (!user.isMfaEnabled()) {
        return ResponseEntity.ok(
            new ApiResponse<>(
                "MFA setup required",
                Map.of(
                    "mfaRequired", true,
                    "redirect", "http://authcenter.madhusudan.space:5000/mfa/setup?userId=" + user.getId()
                        + "&redirect=" + URLEncoder.encode(req.getRedirect(), StandardCharsets.UTF_8)
                ),
                200
            )
        );
    }

    // If MFA enabled → verification page
    // After MFA, cookies are set in MFA controller, not here
    return ResponseEntity.ok(
        new ApiResponse<>(
            "MFA verification required",
            Map.of(
                "mfaRequired", true,
                "redirect", "http://authcenter.madhusudan.space:5000/mfa/verify-page?userId=" + user.getId()
                    + "&redirect=" + URLEncoder.encode(req.getRedirect(), StandardCharsets.UTF_8)
            ),
            200
        )
    );
    }

    @PostMapping("/otp")
    public ResponseEntity<?> generateOtp(@Valid @RequestBody OtpRequest otpRequest) {
        if (!recaptchaService.isCaptchaValid(otpRequest.getCaptchaToken())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>("Invalid CAPTCHA", null, 403));
        }

        if (otpRequest.getEmail() == null || otpRequest.getEmail().trim().isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>("Email is required", null, 400));
        }

        if (otpRequest.getOtpRequiredFor() == null) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>("Please specify the otp required reason", null, 400));
        }

        otpService.generateAndSendOtp(otpRequest.getEmail(), otpRequest.getOtpRequiredFor());
        return ResponseEntity.ok(new ApiResponse<>("OTP sent successfully", null, 200));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest req) {
        if (!recaptchaService.isCaptchaValid(req.getCaptchaToken())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>("Invalid CAPTCHA", null, 403));
        }

        Role roleEnum;
        try {
            roleEnum = Role.valueOf(req.getRole().toUpperCase());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse<>("Invalid role", null, 400));
        }

        // Approve users automatically, reject others
        String approvalString = null;
        Status status;
        if (roleEnum == Role.USER) {
            status = Status.APPROVED;
        } else {
            status = Status.PENDING;
            approvalString = StringGenerator.generateRandomString(16);
        }

        String redirectHost = UrlUtils.extractHost(req.getRedirect());

        Optional<User> existingUserOpt = userService.findByEmailAndApplication(req.getEmail(), redirectHost);
        User user;

        if (existingUserOpt.isPresent()) {
            user = existingUserOpt.get();
            boolean hasRole = user.getRoles().stream()
                    .anyMatch(r -> r.getRole() == roleEnum);

            if (hasRole) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ApiResponse<>("User already exists with this role in the application", null, 400));
            }

            if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ApiResponse<>("Invalid email or password", null, 401));
            }

            user.setPassword(passwordEncoder.encode(req.getPassword()));
            user.addRole(roleEnum, approvalString, status);

        } else {
            user = new User();
            user.setEmail(req.getEmail());
            user.setPassword(passwordEncoder.encode(req.getPassword()));
            user.setName(req.getEmail().split("@")[0]);
            user.setApplication(redirectHost);
            user.addRole(roleEnum, approvalString, status);
        }

        user = userService.save(user);

        if (roleEnum == Role.USER) {
            emailService.sendRegistrationSuccess(req.getEmail(), redirectHost);
        } else {
            emailService.sendApprovalRequest(
                    superAdminEmail,
                    user.getId().toString(),
                    approvalString,
                    user.getEmail(),
                    roleEnum
            );
        }

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new ApiResponse<>("Registration successful", null, 201));
    }

    @PostMapping("/user-exists")
    public ResponseEntity<ApiResponse<Boolean>> checkUserExists(@RequestBody UserExistsRequest req) {
        String redirectHost = UrlUtils.extractHost(req.getRedirect());
        Boolean existingUserOpt = userService.existsByEmailAndApplication(req.getEmail(), redirectHost);

        if(existingUserOpt){
            return ResponseEntity.ok(
                    new ApiResponse<>("User already exists with one of role in the application", existingUserOpt, 200)
            );
        }
        return ResponseEntity.ok(
                new ApiResponse<>("User is new to the application", existingUserOpt, 200)
        );
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ForgotPasswordRequest req) {
        if (!recaptchaService.isCaptchaValid(req.getCaptchaToken())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>("Invalid CAPTCHA", null, 403));
        }

        if (!otpService.validateOtp(req.getEmail(), req.getOtp())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse<>("Invalid or expired OTP", null, 400));
        }

        String redirectHost = null;
        try {
            URI redirectUri = new URI(req.getRedirect());
            redirectHost = redirectUri.getHost();
        } catch (URISyntaxException e) {
            redirectHost = req.getRedirect();
        }

        Optional<User> userOpt = userService.findByEmailAndApplication(req.getEmail(), redirectHost);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>("User not found", null, 404));
        }

        User user = userOpt.get();
        user.setPassword(passwordEncoder.encode(req.getNewPassword()));
        userService.save(user);

        emailService.sendPasswordResetSuccess(req.getEmail(), redirectHost );

        return ResponseEntity.ok(new ApiResponse<>("Password reset successful", null, 200));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response, HttpServletRequest request) {
        // Remove cookies for the correct domain (per-app)
        String cookieDomain = null;
        String referer = request.getHeader("Referer");
        if (referer != null) {
            try {
                URI refererUri = new URI(referer);
                String host = refererUri.getHost();
                if (host != null) {
                    cookieDomain = "." + host;
                }
            } catch (Exception ignored) {}
        }
        if (cookieDomain == null) {
            String reqHost = request.getServerName();
            if (reqHost != null) {
                cookieDomain = "." + reqHost;
            } else {
                cookieDomain = ".madhusudan.space";
            }
        }

        // Remove access token
        Cookie accessCookie = new Cookie("auth_token", null);
        accessCookie.setMaxAge(0);
        accessCookie.setHttpOnly(true);
        accessCookie.setSecure(request.isSecure());
        accessCookie.setPath("/");
        accessCookie.setDomain(cookieDomain);
        response.addCookie(accessCookie);

        // Remove refresh token
        Cookie refreshCookie = new Cookie("refresh_token", null);
        refreshCookie.setMaxAge(0);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(request.isSecure());
        refreshCookie.setPath("/");
        refreshCookie.setDomain(cookieDomain);
        response.addCookie(refreshCookie);

        return ResponseEntity.ok(new ApiResponse<>("Logged out successfully", null, 200));
    }

}
