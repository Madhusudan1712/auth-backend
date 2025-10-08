package com.authcenter.auth_backend.service;

import com.authcenter.auth_backend.dto.request.OtpRequest;
import com.authcenter.auth_backend.model.OtpPurpose;

public interface OtpService {
    String generateAndSendOtp(OtpRequest otpRequest);
    boolean validateAndConsumeOtp(String sessionId, String email, String otp, OtpPurpose purpose);
    void cleanupExpiredOtps();
}