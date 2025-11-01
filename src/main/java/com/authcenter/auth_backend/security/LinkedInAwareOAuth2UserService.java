package com.authcenter.auth_backend.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Augments LinkedIn OAuth2 user with email and name fields.
 * For all other providers, it simply delegates to the default service.
 */
@Component
public class LinkedInAwareOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private static final String LINKEDIN_REGISTRATION_ID = "linkedin";
    private static final String LINKEDIN_EMAIL_ENDPOINT =
            "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))";

    private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        OAuth2User user = delegate.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        if (!LINKEDIN_REGISTRATION_ID.equalsIgnoreCase(registrationId)) {
            return user;
        }

        Map<String, Object> attributes = new HashMap<>(user.getAttributes());

        // Derive name from LinkedIn attributes when possible
        String name = deriveName(attributes);
        if (name != null && !name.isBlank()) {
            attributes.put("name", name);
        }

        // Fetch primary email and add to attributes
        String accessToken = userRequest.getAccessToken().getTokenValue();
        String email = fetchLinkedInEmail(accessToken);
        if (email != null && !email.isBlank()) {
            attributes.put("email", email);
        }

        Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
        String nameAttributeKey = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        return new DefaultOAuth2User(authorities, attributes, nameAttributeKey);
    }

    private String deriveName(Map<String, Object> attrs) {
        // Try modern fields first
        Object lf = attrs.get("localizedFirstName");
        Object ll = attrs.get("localizedLastName");
        if (lf instanceof String || ll instanceof String) {
            String first = lf == null ? "" : lf.toString();
            String last = ll == null ? "" : ll.toString();
            return (first + " " + last).trim();
        }
        // Fallbacks
        Object formatted = attrs.get("formattedName");
        if (formatted instanceof String s && !s.isBlank()) {
            return s;
        }
        return null;
    }

    private String fetchLinkedInEmail(String accessToken) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(LINKEDIN_EMAIL_ENDPOINT))
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                    .GET()
                    .build();

            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (resp.statusCode() >= 200 && resp.statusCode() < 300) {
                JsonNode root = objectMapper.readTree(resp.body());
                JsonNode elements = root.path("elements");
                if (elements.isArray() && elements.size() > 0) {
                    JsonNode handle = elements.get(0).path("handle~");
                    JsonNode email = handle.path("emailAddress");
                    if (!email.isMissingNode()) {
                        return email.asText();
                    }
                }
            }
        } catch (IOException | InterruptedException ignored) {
            // Intentionally ignore; absence of email will be handled downstream
        }
        return null;
    }
}
