package com.authcenter.auth_backend.repository;

import com.authcenter.auth_backend.model.OtpToken;
import com.authcenter.auth_backend.model.OtpPurpose;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Optional;

public interface OtpTokenRepository extends JpaRepository<OtpToken, Long> {
    
    Optional<OtpToken> findBySessionIdAndEmailAndOtpPurpose(String sessionId, String email, OtpPurpose purpose);
    
    Optional<OtpToken> findByEmailAndApplicationAndOtpPurpose(String email, String application, OtpPurpose purpose);
    
    // @Query is required here because we need to check both used=false and expiresAt conditions
    @Query("SELECT ot FROM OtpToken ot WHERE ot.email = :email AND ot.otpPurpose = :purpose AND ot.used = false AND ot.expiresAt > CURRENT_TIMESTAMP")
    Optional<OtpToken> findActiveOtpByEmailAndPurpose(@Param("email") String email, @Param("purpose") OtpPurpose purpose);
    
    // @Query is required here because we need to perform a delete operation with custom conditions
    @Modifying
    @Query("DELETE FROM OtpToken ot WHERE ot.expiresAt < :expiryTime OR ot.used = true")
    void deleteByExpiresAtBeforeOrUsedTrue(@Param("expiryTime") LocalDateTime expiryTime);
    
    // @Query is required here because we need to perform a count operation with specific conditions
    @Query("SELECT COUNT(ot) > 0 FROM OtpToken ot WHERE ot.email = :email AND ot.otpPurpose = :purpose AND ot.updated > :sinceTime")
    boolean existsRecentAttempt(@Param("email") String email, 
                              @Param("purpose") OtpPurpose purpose, 
                              @Param("sinceTime") LocalDateTime sinceTime);
}
