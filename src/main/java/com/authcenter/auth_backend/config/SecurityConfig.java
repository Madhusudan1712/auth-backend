package com.authcenter.auth_backend.config;

import com.authcenter.auth_backend.repository.UserRepository;
import com.authcenter.auth_backend.security.LinkedInAwareOAuth2UserService;
import com.authcenter.auth_backend.security.JwtAuthenticationFilter;
import com.authcenter.auth_backend.security.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

@Configuration
@Profile("!test")
public class SecurityConfig {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Value("${authcenter.cors.allowed-origins}")
    private String[] allowedOrigins;

    @Value("${authcenter.cors.local-extra-origins:}")
    private String[] localExtraOrigins;

    @Value("${spring.profiles.active:}")
    private String activeProfile;

    public SecurityConfig(JwtService jwtService, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   ClientRegistrationRepository clientRegistrationRepository,
                                                   LinkedInAwareOAuth2UserService linkedInAwareOAuth2UserService) throws Exception {
        http
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();

                    List<String> patterns = buildAllowedOriginPatterns();
                    log.info("CORS allowed origin patterns: {}", patterns);

                    config.setAllowedOriginPatterns(patterns);
                    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                    config.setAllowedHeaders(List.of("*"));
                    config.setExposedHeaders(List.of("Set-Cookie", "Authorization", "Location"));
                    config.setAllowCredentials(true);
                    config.setMaxAge(3600L);

                    return config;
                }))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/auth/**",
                                "/oauth2/**",
                                "/login/oauth2/**",
                                "/approval/**",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/healthz",
                                "/actuator/health",
                                "/actuator/health/*",
                                "/actuator/info"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex.authenticationEntryPoint(unauthorizedEntryPoint()))
                .oauth2Login(oauth -> oauth
                        .authorizationEndpoint(auth -> auth
                                .authorizationRequestResolver(
                                        customAuthorizationRequestResolver(clientRegistrationRepository)
                                )
                        )
                        .redirectionEndpoint(red -> red
                                .baseUri("/oauth2/callback/*")
                        )
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(linkedInAwareOAuth2UserService)
                        )
                        .successHandler((request, response, authentication) -> {
                            // must exist (set by ?redirect= param before OAuth starts)
                            String redirectUri = (String) request.getSession().getAttribute("redirect_uri");

                            if (!StringUtils.hasText(redirectUri)) {
                                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing redirect parameter");
                                return;
                            }

                            // forward to OAuthController which handles cookies + validation
                            response.sendRedirect("/oauth2/success?redirect=" + redirectUri);
                        })
                        .failureUrl("/auth/login?error=true")
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/auth/logout")
                        .deleteCookies("auth_token", "refresh_token")
                )
                .addFilterBefore(new JwtAuthenticationFilter(jwtService, userRepository),
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public OAuth2AuthorizationRequestResolver customAuthorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {

        DefaultOAuth2AuthorizationRequestResolver defaultResolver =
                new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");

        return new OAuth2AuthorizationRequestResolver() {
            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
                OAuth2AuthorizationRequest authRequest = defaultResolver.resolve(request);
                return captureRedirect(request, authRequest);
            }

            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
                OAuth2AuthorizationRequest authRequest = defaultResolver.resolve(request, clientRegistrationId);
                return captureRedirect(request, authRequest);
            }

            private OAuth2AuthorizationRequest captureRedirect(HttpServletRequest request,
                                                               OAuth2AuthorizationRequest authRequest) {
                if (authRequest == null) {
                    return null;
                }

                String redirect = request.getParameter("redirect");
                if (StringUtils.hasText(redirect)) {
                    request.getSession().setAttribute("redirect_uri", redirect);
                }
                return authRequest;
            }
        };
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationEntryPoint unauthorizedEntryPoint() {
        return new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);
    }

    private List<String> buildAllowedOriginPatterns() {
        List<String> entries = new java.util.ArrayList<>();
        // Always include configured origins
        entries.addAll(Arrays.stream(allowedOrigins == null ? new String[]{} : allowedOrigins)
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList());

        boolean isProd = activeProfile != null && (activeProfile.contains("prod") || activeProfile.contains("production"));
        if (!isProd) {
            // Local conveniences
            entries.add("localhost");
            entries.add("127.0.0.1");
            entries.addAll(Arrays.stream(localExtraOrigins == null ? new String[]{} : localExtraOrigins)
                    .filter(Objects::nonNull)
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .toList());
        }

        List<String> patterns = new java.util.ArrayList<>();
        for (String domain : entries) {
            String cleaned = domain.replaceFirst("^https?://", "").replaceAll("/+\\z", "");
            // Base host (any default port)
            patterns.add("http://" + cleaned);
            patterns.add("https://" + cleaned);
            // Any subdomain
            patterns.add("http://*." + cleaned);
            patterns.add("https://*." + cleaned);

            // In non-prod
            if (!isProd) {
                patterns.add("http://" + cleaned + ":*");
                patterns.add("https://" + cleaned + ":*");
                patterns.add("http://*." + cleaned + ":*");
                patterns.add("https://*." + cleaned + ":*");
            }
        }

        return patterns;
    }
}
