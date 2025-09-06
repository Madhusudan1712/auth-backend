package com.authcenter.auth_backend.repository;

import com.authcenter.auth_backend.model.Role;
import com.authcenter.auth_backend.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findById(UUID id);
    Optional<User> findByEmail(String email);
    Optional<User> findByEmailAndApplication(String email, String application);
    boolean existsByEmailAndApplication(String email, String application);
    boolean existsByEmail(String email);
    boolean existsByEmailAndApplicationAndRolesRole(String email, String application, Role role);
    Optional<User> findByEmailAndApplicationAndRolesRole(String email, String application, Role role);
}
