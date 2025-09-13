package com.authcenter.auth_backend.model;

public enum OtpPurpose {
    SIGNUP("Account Registration"),
    FORGOT_PASSWORD("Password Reset");

    private final String displayName;

    OtpPurpose(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
