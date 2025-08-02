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

    @Value("${jwt.expiration.ms:86400000}") // 1 day
    private long jwtExpirationMs;

    public OAuthController(UserRepository userRepository, JwtService jwtService) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }

    @GetMapping("/oauth2/success")
    public ResponseEntity<?> oauth2Success(OAuth2AuthenticationToken authentication, HttpServletResponse response) {
        Map<String, Object> attributes = authentication.getPrincipal().getAttributes();

        String email = (String) attributes.get("email");
        String name = (String) attributes.getOrDefault("name", email.split("@")[0]);
        String domain = email.split("@")[1];

        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setEmail(email);
                    newUser.setName(name);
                    newUser.setDomain(domain);
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
        claims.put("domain", user.getDomain());

        String token = jwtService.generateToken(claims, user.getEmail(), jwtExpirationMs);

        Cookie cookie = new Cookie("auth_token", token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge((int) Duration.ofMillis(jwtExpirationMs).getSeconds());
        cookie.setDomain("local.authcenter.com"); // adjust in production
        response.addCookie(cookie);

        return ResponseEntity.ok(new ApiResponse<>("OAuth2 login successful", null, 200));
    }
}
