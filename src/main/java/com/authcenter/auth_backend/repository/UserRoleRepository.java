package com.authcenter.auth_backend.repository;

import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.model.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface UserRoleRepository extends JpaRepository<UserRole, UUID> {
    List<UserRole> findAllByUser(User user);
    Optional<UserRole> findByApprovalString(String approvalString);
}
