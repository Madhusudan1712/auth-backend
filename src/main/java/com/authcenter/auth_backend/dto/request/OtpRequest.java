package com.authcenter.auth_backend.dto.request;

import com.authcenter.auth_backend.model.OtpPurpose;

public class OtpRequest {
    private String email;
    private String application;
    private OtpPurpose otpPurpose;
    private String captchaToken;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getApplication() {
        return application;
    }

    public void setApplication(String application) {
        this.application = application;
    }

    public OtpPurpose getOtpPurpose() {
        return otpPurpose;
    }

    public void setOtpPurpose(OtpPurpose otpPurpose) {
        this.otpPurpose = otpPurpose;
    }

    public String getCaptchaToken() {
        return captchaToken;
    }

    public void setCaptchaToken(String captchaToken) {
        this.captchaToken = captchaToken;
    }
}
