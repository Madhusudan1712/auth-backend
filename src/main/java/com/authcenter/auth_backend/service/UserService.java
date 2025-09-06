package com.authcenter.auth_backend.service;

import com.authcenter.auth_backend.model.Role;
import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final EmailService emailService;

    public UserService(UserRepository userRepository,
                       EmailService emailService) {
        this.userRepository = userRepository;
        this.emailService = emailService;
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public Optional<User> findByEmailAndApplication(String email, String application) {
        return userRepository.findByEmailAndApplication(email, application);
    }

    public Boolean existsByEmailAndApplication(String email, String application) {
        return userRepository.existsByEmailAndApplication(email, application);
    }

    public boolean existsByEmailRoleApplication(String email, Role role, String application) {
        return userRepository.existsByEmailAndApplicationAndRolesRole(email, application, role);
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    public User save(User user) {
        return userRepository.save(user);
    }

}