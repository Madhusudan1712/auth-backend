package com.authcenter.auth_backend.dto.request;

public class OtpRequest {
    private String email;
    private String otpRequiredFor;
    private String captchaToken;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getOtpRequiredFor() {
        return otpRequiredFor;
    }

    public void setOtpRequiredFor(String otpRequiredFor) {
        this.otpRequiredFor = otpRequiredFor;
    }

    public String getCaptchaToken() {
        return captchaToken;
    }

    public void setCaptchaToken(String captchaToken) {
        this.captchaToken = captchaToken;
    }
}
