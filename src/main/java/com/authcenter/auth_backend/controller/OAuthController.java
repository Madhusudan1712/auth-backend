package com.authcenter.auth_backend.controller;

import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.repository.UserRepository;
import com.authcenter.auth_backend.security.JwtService;
import com.authcenter.auth_backend.util.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

@RestController
public class OAuthController {

    private final UserRepository userRepository;
    private final JwtService jwtService;

    @Value("${jwt.access.expiration.ms:900000}")
    private long jwtAccessExpirationMs;

    @Value("${jwt.refresh.expiration.ms:604800000}")
    private long jwtRefreshExpirationMs;

    @Value("${authcenter.cors.allowed-origins}")
    private String[] allowedRedirectOrigins;

    public OAuthController(UserRepository userRepository, JwtService jwtService) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }

    @GetMapping("/oauth2/success")
    public void oauth2Success(
            @RequestParam(name = "redirect", required = false) String redirect,
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> attributes = new HashMap<>();

        if (authentication instanceof OAuth2AuthenticationToken oauth2Auth) {
            attributes = oauth2Auth.getPrincipal().getAttributes();
        } else if (authentication.getPrincipal() instanceof User user) {
            // JwtAuthenticationFilter replaced the principal already
            attributes.put("email", user.getEmail());
            attributes.put("name", user.getName());
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "No valid OAuth2 or User principal found");
            return;
        }

        String email = (String) attributes.get("email");
        String name = (String) attributes.getOrDefault("name", email.split("@")[0]);

        String tempRedirectHost;
        try {
            URI redirectUri = new URI(redirect);
            tempRedirectHost = redirectUri.getHost();
        } catch (URISyntaxException e) {
            tempRedirectHost = redirect;
        }

        final String redirectHost = tempRedirectHost;

        // Fetch or create user
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setEmail(email);
                    newUser.setName(name);
                    newUser.setApplication(redirectHost);
                    newUser.setRole("user");
                    newUser.setApproved(true);
                    return userRepository.save(newUser);
                });

        if (!user.isApproved()) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Account not approved yet");
            return;
        }

        // ✅ MFA check — behaves like /auth/login
        if (!user.isMfaEnabled()) {
            // Force MFA setup
            String mfaSetupUrl = "http://authcenter.madhusudan.space:5000/mfa/setup?userId=" + user.getId()
                    + "&redirect=" + URLEncoder.encode(redirect, StandardCharsets.UTF_8);
            response.sendRedirect(mfaSetupUrl);
            return;
        } else {
            // MFA already enabled → redirect to verify page
            String mfaVerifyUrl = "http://authcenter.madhusudan.space:5000/mfa/verify-page?userId=" + user.getId()
                    + "&redirect=" + URLEncoder.encode(redirect, StandardCharsets.UTF_8);
            response.sendRedirect(mfaVerifyUrl);
            return;
        }
    }
}
