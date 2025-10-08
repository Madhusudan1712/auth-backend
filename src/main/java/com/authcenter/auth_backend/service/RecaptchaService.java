package com.authcenter.auth_backend.service;

public interface RecaptchaService {
    boolean isCaptchaValid(String token);
}