package com.authcenter.auth_backend.service;

import com.authcenter.auth_backend.model.Role;
import com.authcenter.auth_backend.model.User;
import java.util.Optional;

public interface UserService {
    Optional<User> findByEmail(String email);
    Optional<User> findByEmailAndApplication(String email, String application);
    Boolean existsByEmailAndApplication(String email, String application);
    boolean existsByEmailRoleApplication(String email, Role role, String application);
    boolean existsByEmail(String email);
    User save(User user);
}