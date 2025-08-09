package com.authcenter.auth_backend.controller;

import com.authcenter.auth_backend.dto.response.ApiResponse;
import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.repository.UserRepository;
import com.authcenter.auth_backend.security.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@RestController
public class OAuthController {

    private final UserRepository userRepository;
    private final JwtService jwtService;

    @Value("${jwt.access.expiration.ms:900000}")
    private long jwtAccessExpirationMs;

    @Value("${jwt.refresh.expiration.ms:604800000}")
    private long jwtRefreshExpirationMs;

    public OAuthController(UserRepository userRepository, JwtService jwtService) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }

    @GetMapping("/oauth2/success")
    public ResponseEntity<?> oauth2Success(String redirect, OAuth2AuthenticationToken authentication, HttpServletResponse response) {
        Map<String, Object> attributes = authentication.getPrincipal().getAttributes();

        String email = (String) attributes.get("email");
        String name = (String) attributes.getOrDefault("name", email.split("@")[0]);

        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setEmail(email);
                    newUser.setName(name);
                    newUser.setApplication(redirect);
                    newUser.setRole("user");
                    newUser.setApproved(true); // Assume approved
                    return userRepository.save(newUser);
                });

        // Generate JWT
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", user.getId().toString());
        claims.put("name", user.getName());
        claims.put("email", user.getEmail());
        claims.put("role", user.getRole());
        claims.put("domain", user.getApplication());

        // Generate access and refresh tokens
        String accessToken = jwtService.generateAccessToken(claims, user.getEmail(), jwtAccessExpirationMs);
        String refreshToken = jwtService.generateRefreshToken(user.getEmail(), jwtRefreshExpirationMs);

        // Set access token in cookie
        Cookie accessCookie = new Cookie("auth_token", accessToken);
        accessCookie.setHttpOnly(true);
        accessCookie.setSecure(false); // true in production with HTTPS
        accessCookie.setPath("/");
        accessCookie.setDomain(".madhusudan.space");
        accessCookie.setMaxAge((int) Duration.ofMillis(jwtAccessExpirationMs).getSeconds());
        response.addCookie(accessCookie);

        // Set refresh token in cookie
        Cookie refreshCookie = new Cookie("refresh_token", refreshToken);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(false); // true in production
        refreshCookie.setPath("/");
        refreshCookie.setDomain(".madhusudan.space");
        refreshCookie.setMaxAge((int) Duration.ofMillis(jwtRefreshExpirationMs).getSeconds());
        response.addCookie(refreshCookie);

        return ResponseEntity.ok(new ApiResponse<>("OAuth2 login successful", null, 200));
    }
}
