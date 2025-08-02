package com.authcenter.auth_backend.service;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Service
public class RecaptchaService {

    @Value("${recaptcha.secret}")
    private String secret;

    public boolean isCaptchaValid(String token) {
        String verifyUrl = "https://www.google.com/recaptcha/api/siteverify";

        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("secret", secret);
        form.add("response", token);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);

        ResponseEntity<JsonNode> response = restTemplate.exchange(
                verifyUrl,
                HttpMethod.POST,
                request,
                JsonNode.class
        );

        JsonNode body = response.getBody();
        return body != null && body.get("success").asBoolean();
    }
}