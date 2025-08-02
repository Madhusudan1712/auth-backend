package com.authcenter.auth_backend.dto.request;

public class RecaptchaRequest {
    private String token;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
