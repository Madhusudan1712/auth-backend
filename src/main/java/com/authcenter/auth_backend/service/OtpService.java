package com.authcenter.auth_backend.service;

import com.authcenter.auth_backend.model.OtpToken;
import com.authcenter.auth_backend.repository.OtpTokenRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Random;

@Service
public class OtpService {

    private final OtpTokenRepository otpTokenRepository;
    private final EmailService emailService;

    public OtpService(OtpTokenRepository otpTokenRepository, EmailService emailService) {
        this.otpTokenRepository = otpTokenRepository;
        this.emailService = emailService;
    }

    public void generateAndSendOtp(String email, String otpRequiredFor) {
        String otp = String.format("%06d", new Random().nextInt(999999));
        OtpToken token = new OtpToken();
        token.setEmail(email);
        token.setOtp(otp);
        token.setExpiresAt(LocalDateTime.now().plusMinutes(10));
        token.setUsed(false);
        otpTokenRepository.save(token);
        emailService.sendOtpEmail(email, otp, otpRequiredFor);
    }

    public boolean validateOtp(String email, String otp) {
        return otpTokenRepository.findByEmailAndOtpAndUsedFalse(email, otp)
                .filter(token -> token.getExpiresAt().isAfter(LocalDateTime.now()))
                .map(token -> {
                    token.setUsed(true);
                    otpTokenRepository.save(token);
                    return true;
                })
                .orElse(false);
    }

    public String issue(String email, int ttlMinutes) {
        String code = String.format("%06d", new Random().nextInt(1_000_000));
        OtpToken t = new OtpToken();
        t.setEmail(email);
        t.setOtp(code);
        t.setExpiresAt(LocalDateTime.now().plusMinutes(ttlMinutes));
        t.setUsed(false);
        otpTokenRepository.save(t);
        return code;
    }

    public boolean consume(String email, String code) {
        return otpTokenRepository.findTopByEmailAndUsedFalseOrderByExpiresAtDesc(email)
                .filter(t -> t.getExpiresAt().isAfter(LocalDateTime.now()))
                .filter(t -> t.getOtp().equals(code))
                .map(t -> { t.setUsed(true); otpTokenRepository.save(t); return true; })
                .orElse(false);
    }
}