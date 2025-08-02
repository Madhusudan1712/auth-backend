package com.authcenter.auth_backend.repository;

import com.authcenter.auth_backend.model.ApprovalRequest;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ApprovalRequestRepository extends JpaRepository<ApprovalRequest, Long> {
    Optional<ApprovalRequest> findByApprovalString(String approvalString);
}
