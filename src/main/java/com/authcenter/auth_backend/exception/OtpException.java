package com.authcenter.auth_backend.exception;

import org.springframework.http.HttpStatus;

public class OtpException extends RuntimeException {
    private final HttpStatus status;

    public OtpException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }

    public OtpException(String message, Throwable cause) {
        super(message, cause);
        this.status = HttpStatus.INTERNAL_SERVER_ERROR;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
