package com.authcenter.auth_backend.service;

import com.authcenter.auth_backend.model.UserRole;
import com.authcenter.auth_backend.repository.UserRoleRepository;
import org.springframework.stereotype.Service;

@Service
public class UserRoleService {
    private final UserRoleRepository userRoleRepository;
    public UserRoleService(UserRoleRepository userRoleRepository) {
        this.userRoleRepository = userRoleRepository;
    }

    public UserRole save(UserRole userRole) {
        return userRoleRepository.save(userRole);
    }

}
