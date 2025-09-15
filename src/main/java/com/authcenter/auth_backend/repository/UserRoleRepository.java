package com.authcenter.auth_backend.repository;

import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.model.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, UUID> {
    List<UserRole> findAllByUser(User user);
    Optional<UserRole> findByApprovalString(String approvalString);
    List<UserRole> findByApprovedFalseAndRejectedFalse();
}
