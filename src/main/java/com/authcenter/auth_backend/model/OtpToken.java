package com.authcenter.auth_backend.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "otp_tokens", 
       uniqueConstraints = @UniqueConstraint(columnNames = {"email", "application", "otpPurpose"}))
public class OtpToken extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    
    @Column(nullable = false)
    private String application;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private OtpPurpose otpPurpose;
    
    @Column(nullable = false)
    private String email;
    
    @Column(nullable = false)
    private String hashedOtp;
    
    @Column(nullable = false, unique = true)
    private String sessionId;
    
    @Column(nullable = false)
    private LocalDateTime expiresAt;
    
    @Column(nullable = false)
    private boolean used = false;
    
    @Column(nullable = false)
    private int attempts = 0;
    
    @Column(nullable = false, length = 64)
    private String salt;
    
    @PrePersist
    protected void onCreate() {
        super.prePersist();
    }

    // Getters and setters

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

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

    public String getHashedOtp() {
        return hashedOtp;
    }

    public void setHashedOtp(String hashedOtp) {
        this.hashedOtp = hashedOtp;
    }
    
    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }
    
    public int getAttempts() {
        return attempts;
    }
    
    public void incrementAttempts() {
        this.attempts++;
        super.preUpdate();
    }
    
    public void setAttempts(int attempts) {
        this.attempts = attempts;
    }
    
    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public boolean isUsed() {
        return used;
    }
    
    public String getSalt() {
        return salt;
    }
    
    public void setSalt(String salt) {
        this.salt = salt;
    }

    public void setUsed(boolean used) {
        this.used = used;
    }
    
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }
    
    public boolean canResend() {
        return LocalDateTime.now().isAfter(getUpdated().plusMinutes(1)); // 1 minute cooldown
    }
    
    public boolean isMaxAttemptsReached() {
        return attempts >= 5;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OtpToken otpToken = (OtpToken) o;
        return Objects.equals(email, otpToken.email) &&
               Objects.equals(application, otpToken.application) &&
               otpPurpose == otpToken.otpPurpose;
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(email, application, otpPurpose);
    }
}
