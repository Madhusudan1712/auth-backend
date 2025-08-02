package com.authcenter.auth_backend.controller;

import com.authcenter.auth_backend.dto.request.*;
import com.authcenter.auth_backend.dto.response.ApiResponse;
import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.security.JwtService;
import com.authcenter.auth_backend.service.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.awt.image.ImagingOpException;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final OtpService otpService;
    private final RecaptchaService recaptchaService;
    private final EmailService emailService;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    @Value("${jwt.expiration.ms:86400000}") // default 1 day
    private long jwtExpirationMs;

    @Value("${authcenter.cors.allowed-origins}")
    private String[] allowedRedirectOrigins;

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

        Optional<User> userOpt = userService.findByEmail(req.getEmail());
        if (userOpt.isEmpty() || !passwordEncoder.matches(req.getPassword(), userOpt.get().getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>("Invalid email or password", null, 401));
        }

        User user = userOpt.get();
        if (!user.isApproved()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>("Account not approved yet", null, 403));
        }

        var claims = new HashMap<String, Object>();
        claims.put("id", user.getId().toString());
        claims.put("name", user.getName());
        claims.put("email", user.getEmail());
        claims.put("role", user.getRole());
        claims.put("domain", req.getRedirect());

        String token = jwtService.generateToken(claims, user.getEmail(), jwtExpirationMs);

        Cookie cookie = new Cookie("auth_token", token);
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // only use true in HTTPS (production)
        cookie.setPath("/");
        //cookie.setDomain(".madhusudan.space");
        cookie.setMaxAge((int) Duration.ofMillis(jwtExpirationMs).getSeconds());
        response.addCookie(cookie);

        // Read ?redirect=... from query string
        String redirectUri = req.getRedirect();
        if (redirectUri != null && !redirectUri.isBlank()) {
            try {
                URI uri = new URI(redirectUri);
                String host = uri.getHost();
                int port = uri.getPort();
                String scheme = uri.getScheme();

                // If port is -1, skip it
                String origin = scheme + "://" + host + (port != -1 ? ":" + port : "");

                boolean isAllowed = Arrays.stream(allowedRedirectOrigins)
                        .map(String::trim)
                        .anyMatch(allowed -> {
                            try {
                                URI allowedUri = new URI(allowed);
                                return allowedUri.getHost() != null
                                        && host != null
                                        && host.equalsIgnoreCase(allowedUri.getHost())
                                        && allowedUri.getPort() == port
                                        && allowedUri.getScheme().equalsIgnoreCase(scheme);
                            } catch (Exception e) {
                                return false;
                            }
                        });

                if (isAllowed) {
                    return ResponseEntity.ok(new ApiResponse<>("Login successful", Map.of("redirect", redirectUri), 200));
                } else {
                    return ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body(new ApiResponse<>("Redirect URI not allowed", null, 403));
                }

            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ApiResponse<>("Invalid redirect URI format", null, 400));
            }
        }

        return ResponseEntity.ok(new ApiResponse<>("Login successful", null, 200));
    }

    @PostMapping("/otp")
    public ResponseEntity<?> generateOtp(@Valid @RequestBody OtpRequest otpRequest) {
        if (otpRequest.getEmail() == null || otpRequest.getEmail().trim().isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse<>("Email is required", null, 400));
        }

        if (!recaptchaService.isCaptchaValid(otpRequest.getCaptchaToken())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>("Invalid CAPTCHA", null, 403));
        }

        otpService.generateAndSendOtp(otpRequest.getEmail());
        return ResponseEntity.ok(new ApiResponse<>("OTP sent successfully", null, 200));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest req) {
        if (!recaptchaService.isCaptchaValid(req.getCaptchaToken())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>("Invalid CAPTCHA", null, 403));
        }

        if (!otpService.validateOtp(req.getEmail(), req.getOtp())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse<>("Invalid or expired OTP", null, 400));
        }

        if (userService.existsByEmail(req.getEmail())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse<>("User already exists", null, 400));
        }

        User user = new User();
        user.setEmail(req.getEmail());
        user.setRole(req.getRole());
        user.setPassword(passwordEncoder.encode(req.getPassword()));
        user.setName(req.getEmail().split("@")[0]);
        user.setDomain(req.getEmail().split("@")[1]);
        user.setApproved(!req.getRole().equalsIgnoreCase("admin"));

        userService.save(user);

        if (req.getRole().equalsIgnoreCase("admin")) {
            userService.triggerAdminApproval(user);
        }

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new ApiResponse<>("Registration successful", null, 201));
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

        Optional<User> userOpt = userService.findByEmail(req.getEmail());
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>("User not found", null, 404));
        }

        User user = userOpt.get();
        user.setPassword(passwordEncoder.encode(req.getNewPassword()));
        userService.save(user);

        return ResponseEntity.ok(new ApiResponse<>("Password reset successful", null, 200));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("auth_token", null);
        cookie.setMaxAge(0);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setDomain("authcenter.madhusudan.space"); // adjust in prod
        response.addCookie(cookie);

        return ResponseEntity.ok(new ApiResponse<>("Logged out successfully", null, 200));
    }
}
