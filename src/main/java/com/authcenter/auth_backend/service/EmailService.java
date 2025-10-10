package com.authcenter.auth_backend.service;

import com.authcenter.auth_backend.model.OtpPurpose;
import com.authcenter.auth_backend.model.Role;
import com.authcenter.auth_backend.model.Status;
import jakarta.mail.MessagingException;
import java.io.UnsupportedEncodingException;

public interface EmailService {
    void sendOtpEmail(String to, String otp, OtpPurpose otpPurpose, String application) throws MessagingException, UnsupportedEncodingException;
    void sendPendingApproval(String to, Role role, String domain);
    void sendRegistrationSuccess(String to, String domain);
    void sendApprovalRequest(String to, String encryptedUserId, String userEmail, Role role);
    void sendApprovedOrRejectedEmail(String to, String domain, Status status, String reason);
    void sendPasswordResetSuccess(String to, String domain);
}
