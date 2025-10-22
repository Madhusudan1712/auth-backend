package com.authcenter.auth_backend.controller;

import com.authcenter.auth_backend.dto.request.*;
import com.authcenter.auth_backend.dto.response.ApiResponse;
import com.authcenter.auth_backend.model.*;
import com.authcenter.auth_backend.security.JwtService;
import com.authcenter.auth_backend.service.*;
import com.authcenter.auth_backend.utils.StringGenerator;
import com.authcenter.auth_backend.utils.CookieUtil;
import com.authcenter.auth_backend.utils.UrlUtils;
import com.authcenter.auth_backend.exception.OtpException;
import com.authcenter.auth_backend.model.OtpPurpose;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final UserService userService;
    private final OtpService otpService;
    private final RecaptchaService recaptchaService;
    private final RefreshTokenService refreshTokenService;
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

    @Value("${base.frontend.url}")
    private String baseFrontendUrl;

    public AuthController(
            UserService userService,
            OtpService otpService,
            RecaptchaService recaptchaService,
            RefreshTokenService refreshTokenService,
            EmailService emailService,
            JwtService jwtService,
            PasswordEncoder passwordEncoder
    ) {
        this.userService = userService;
        this.otpService = otpService;
        this.recaptchaService = recaptchaService;
        this.refreshTokenService = refreshTokenService;
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

        // Validate token signature + expiry
        if (!jwtService.validateToken(refreshToken) || jwtService.isTokenExpired(refreshToken)) {
            return ResponseEntity.status(401).body(new ApiResponse<>("Invalid or expired refresh token", null, 401));
        }

        // Check DB for refresh token
        Optional<RefreshToken> storedToken = refreshTokenService.findByToken(refreshToken);
        if (storedToken.isEmpty()) {
            return ResponseEntity.status(401).body(new ApiResponse<>("Refresh token not found", null, 401));
        }

        // Rotate token: delete old + issue new one
        refreshTokenService.delete(storedToken.get());

        String email = jwtService.extractEmail(refreshToken);
        User user = userService.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Prepare claims for new access token
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

        // Generate new tokens
        String newAccessToken = jwtService.generateAccessToken(claims, email, jwtAccessExpirationMs);
        String newRefreshToken = jwtService.generateRefreshToken(email, jwtRefreshExpirationMs);

        // Save new refresh token in DB
        refreshTokenService.save(newRefreshToken, user.getId(), jwtRefreshExpirationMs);

        //get domain or subdomain
        String referer = request.getHeader("Referer");
        String cookieDomain = (referer != null && !referer.isBlank())
                ? UrlUtils.extractHost(referer)
                : request.getServerName();

        // Update cookies
        CookieUtil.addAuthCookies(
                request,
                response,
                newAccessToken,
                newRefreshToken,
                jwtAccessExpirationMs,
                jwtRefreshExpirationMs,
                cookieDomain
        );

        return ResponseEntity.ok(new ApiResponse<>(
                "Access token refreshed",
                Map.of("accessToken", newAccessToken),
                200
        ));
    }

    @GetMapping("/roles")
    public ApiResponse<List<Map<String, String>>> getRoles() {
        List<Map<String, String>> roles = Arrays.stream(Role.values())
                .map(role -> Map.of("name", role.name(), "label", role.getDisplayName()))
                .collect(Collectors.toList());

        return new ApiResponse<>("Roles fetched successfully", roles, 200);
    }

    @GetMapping("/privileged-access-roles")
    public ApiResponse<List<Map<String, String>>> getPrivilegedAccessRoles() {
        List<Map<String, String>> privilegedAccessRoles = Arrays.stream(PrivilegedAccessRole.values())
                .map(privilegedAccessRole -> Map.of("name", privilegedAccessRole.name(), "label", privilegedAccessRole.getDisplayName()))
                .collect(Collectors.toList());

        return new ApiResponse<>("Privileged access roles fetched successfully", privilegedAccessRoles, 200);
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
                    "redirect", baseFrontendUrl+"/mfa/setup?userId=" + user.getId()
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
                "redirect", baseFrontendUrl+"/mfa/verify-page?userId=" + user.getId()
                    + "&redirect=" + URLEncoder.encode(req.getRedirect(), StandardCharsets.UTF_8)
            ),
            200
        )
    );
    }

    @PostMapping("/otp")
    public ResponseEntity<ApiResponse<Map<String, String>>> generateOtp(
            @Valid @RequestBody OtpRequest otpRequest,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        log.debug("Received OTP request for email: {}", otpRequest.getEmail());

        // Validate required fields
        if (otpRequest.getEmail() == null || otpRequest.getEmail().trim().isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>("Email is required", null, 400));
        }

        if (otpRequest.getOtpPurpose() == null) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>("OTP purpose is required", null, 400));
        }

        if (otpRequest.getApplication() == null || otpRequest.getApplication().trim().isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>("Application (host domain) is required", null, 400));
        }

        // Validate reCAPTCHA
        log.debug("Validating reCAPTCHA token");
        if (!recaptchaService.isCaptchaValid(otpRequest.getCaptchaToken())) {
            log.warn("reCAPTCHA verification failed");
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>("reCAPTCHA verification failed", null, 400));
        }

        try {
            // Generate and send OTP, get session ID
            log.debug("Generating OTP for email: {}", otpRequest.getEmail());
            String sessionId = otpService.generateAndSendOtp(otpRequest);

            // Set session ID in HTTP-only cookie
            CookieUtil.setOtpSessionCookie(request, response, sessionId, otpRequest.getApplication(), 600); // 600 seconds = 10 minutes

            // Prepare response data
            Map<String, String> responseData = new HashMap<>();
            responseData.put("message", "OTP sent successfully");
            responseData.put("email", otpRequest.getEmail());
            responseData.put("sessionId", sessionId);

            return ResponseEntity.ok(new ApiResponse<>("OTP sent successfully", responseData, 200));

        } catch (OtpException e) {
            log.error("OTP generation failed: {}", e.getMessage(), e);
            return ResponseEntity.status(e.getStatus())
                    .body(new ApiResponse<>(e.getMessage(), null, e.getStatus().value()));
        } catch (Exception e) {
            log.error("Unexpected error during OTP generation: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>("Failed to generate OTP. Please try again.", null, 500));
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest req, HttpServletRequest request) {
        log.info("Received signup request for email: {}", req.getEmail());
        log.debug("Signup request details: {}", req);

        // 1. Validate CAPTCHA
        if (!recaptchaService.isCaptchaValid(req.getCaptchaToken())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>("Invalid CAPTCHA", null, 403));
        }

        // 2. Validate Role
        Role selectedRole;
        try {
            selectedRole = Role.valueOf(req.getRole().toUpperCase());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse<>("Invalid role", null, 400));
        }

        // 3. Determine approval status
        String approvalString = null;
        Status status = (selectedRole == Role.USER) ? Status.APPROVED : Status.PENDING;
        if (status == Status.PENDING) {
            approvalString = StringGenerator.generateRandomString(16);
        }

        // 4. Extract application host
        String redirectHost = UrlUtils.extractHost(req.getRedirect());

        // 5. Check if user already exists
        Optional<User> existingUserOpt = userService.findByEmailAndApplication(req.getEmail(), redirectHost);
        User user;

        if (existingUserOpt.isPresent()) {
            user = existingUserOpt.get();

            // 5.1 Check if role already exists for the user
            Optional<UserRole> userRoleOpt = user.getRoles().stream()
                    .filter(r -> r.getRole() == selectedRole)
                    .findFirst();

            if (userRoleOpt.isPresent()) {
                UserRole userRole = userRoleOpt.get();

                // Case 1: Role exists in application
                if (userRole.isApproved() && !userRole.isRejected()) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(new ApiResponse<>(
                                    String.format("User account exists with the role: %s", selectedRole.name() + ", in " + redirectHost),
                                    null,
                                    400
                            ));
                }

                // Case 2: Role exists but pending approval
                if (!userRole.isApproved() && !userRole.isRejected()) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(new ApiResponse<>(
                                    String.format("User account exists, but not yet approved for role: %s", selectedRole.name()),
                                    null,
                                    400
                            ));
                }

                // Case 3: Role exists but rejected by super admin
                if (!userRole.isApproved() && userRole.isRejected()) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(new ApiResponse<>(
                                    String.format("User account exists, but rejected by super admin for role: %s", selectedRole.name()),
                                    null,
                                    400
                            ));
                }
            }

            // 5.2 Validate existing user's password
            if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ApiResponse<>("Invalid email or password", null, 401));
            }

            // 5.3 Validate OTP for existing user adding a new role
            String sessionId = CookieUtil.getSessionIdFromCookies(request);
            if (sessionId == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ApiResponse<>("OTP session not found", null, 400));
            }

            try {
                // Validate OTP - will throw OtpException if invalid
                otpService.validateAndConsumeOtp(sessionId, req.getEmail(), req.getOtp(), OtpPurpose.SIGNUP);
            } catch (OtpException e) {
                return ResponseEntity.status(e.getStatus())
                        .body(new ApiResponse<>(e.getMessage(), null, e.getStatus().value()));
            }

        } else {
            // 6. Create a new user if not exists
            String sessionId = CookieUtil.getSessionIdFromCookies(request);
            if (sessionId == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ApiResponse<>("OTP session not found", null, 400));
            }

            try {
                // Validate OTP - will throw OtpException if invalid
                otpService.validateAndConsumeOtp(sessionId, req.getEmail(), req.getOtp(), OtpPurpose.SIGNUP);
            } catch (OtpException e) {
                return ResponseEntity.status(e.getStatus())
                        .body(new ApiResponse<>(e.getMessage(), null, e.getStatus().value()));
            }

            user = new User();
            user.setEmail(req.getEmail());
            user.setPassword(passwordEncoder.encode(req.getPassword()));
            user.setName(req.getEmail().split("@")[0]);
            user.setApplication(redirectHost);
        }
        user.addRole(selectedRole, approvalString, status);

        log.debug("Creating new user with email: {}", req.getEmail());

        // 7. Save user
        user = userService.save(user);
        log.info("User created successfully with ID: {}", user.getId());

        // 8. Send appropriate email
        boolean requiresApproval = false;
        try {
            requiresApproval = Arrays.stream(PrivilegedAccessRole.values())
                    .anyMatch(privilegedRole -> privilegedRole.name().equals(selectedRole.name()));
        } catch (Exception e) {
            log.warn("Error checking privileged access role for {}", selectedRole, e);
        }

        if (!requiresApproval) {
            emailService.sendRegistrationSuccess(req.getEmail(), redirectHost);
        } else {
            emailService.sendApprovalRequest(
                    superAdminEmail,
                    user.getId().toString(),
                    user.getEmail(),
                    selectedRole
            );
            emailService.sendPendingApproval(req.getEmail(), selectedRole, redirectHost);
        }

        // 9. Return success response
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
    public ResponseEntity<?> resetPassword(
            @Valid @RequestBody ForgotPasswordRequest req,
            HttpServletRequest request
    ) {
        // Validate CAPTCHA
        if (!recaptchaService.isCaptchaValid(req.getCaptchaToken())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>("Invalid CAPTCHA", null, 403));
        }

        // Get session ID from cookies
        String sessionId = CookieUtil.getSessionIdFromCookies(request);
        if (sessionId == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse<>("OTP session not found", null, 400));
        }

        // Validate OTP
        try {
            if (!otpService.validateAndConsumeOtp(sessionId, req.getEmail(), req.getOtp(), OtpPurpose.FORGOT_PASSWORD)) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ApiResponse<>("Invalid or expired OTP", null, 400));
            }
        } catch (OtpException e) {
            return ResponseEntity.status(e.getStatus())
                    .body(new ApiResponse<>(e.getMessage(), null, e.getStatus().value()));
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
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        String cookieDomain = null;
        String referer = request.getHeader("Referer");
        if (referer != null) {
            cookieDomain = UrlUtils.extractHost(referer);
        }
        if (cookieDomain == null || cookieDomain.isBlank()) {
            cookieDomain = request.getServerName();
        }

        boolean isLocal = !request.isSecure()
                && !"https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto"));

        CookieUtil.clearAuthCookies(request, response, cookieDomain, isLocal);

        return ResponseEntity.ok(new ApiResponse<>("Logged out successfully", null, 200));
    }

}
