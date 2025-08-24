package com.authcenter.auth_backend.controller;

import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.repository.UserRepository;
import com.authcenter.auth_backend.security.JwtService;
import com.authcenter.auth_backend.util.CookieUtil;
import jakarta.servlet.http.Cookie;
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
import java.time.Duration;
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
            // If JwtAuthenticationFilter already replaced the principal
            attributes.put("email", user.getEmail());
            attributes.put("name", user.getName());
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "No valid OAuth2 or User principal found");
            return;
        }

        String email = (String) attributes.get("email");
        String name = (String) attributes.getOrDefault("name", email.split("@")[0]);

        // Fetch or create user
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setEmail(email);
                    newUser.setName(name);
                    newUser.setApplication(redirect);
                    newUser.setRole("user");
                    newUser.setApproved(true);
                    return userRepository.save(newUser);
                });

        if (!user.isApproved()) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Account not approved yet");
            return;
        }

        // Claims
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", user.getId().toString());
        claims.put("name", user.getName());
        claims.put("email", user.getEmail());
        claims.put("role", user.getRole());
        claims.put("application", user.getApplication());

        // Generate tokens
        String accessToken = jwtService.generateAccessToken(claims, user.getEmail(), jwtAccessExpirationMs);
        String refreshToken = jwtService.generateRefreshToken(user.getEmail(), jwtRefreshExpirationMs);

        CookieUtil.addAuthCookies(request, response, accessToken, refreshToken, jwtAccessExpirationMs, jwtRefreshExpirationMs);

        // Validate redirect
        if (redirect != null && !redirect.isBlank()) {
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

                if (isAllowed) {
                    // ✅ redirect browser to client app
                    response.sendRedirect(redirect);
                    return;
                } else {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Redirect URI not allowed");
                    return;
                }
            } catch (Exception e) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid redirect URI format");
                return;
            }
        }

        // fallback if no redirect param
        response.sendRedirect("https://authcenter.madhusudan.space");
    }
}
