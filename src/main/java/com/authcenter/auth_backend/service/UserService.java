package com.authcenter.auth_backend.service;

import com.authcenter.auth_backend.model.ApprovalRequest;
import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.repository.ApprovalRequestRepository;
import com.authcenter.auth_backend.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final ApprovalRequestRepository approvalRequestRepository;
    private final EmailService emailService;

    @Value("${authcenter.super.admin.email}")
    private String superAdminEmail;

    @Value("${authcenter.approval.link.base}")
    private String approvalLinkBase;

    public UserService(UserRepository userRepository,
                       ApprovalRequestRepository approvalRequestRepository,
                       EmailService emailService) {
        this.userRepository = userRepository;
        this.approvalRequestRepository = approvalRequestRepository;
        this.emailService = emailService;
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    public void save(User user) {
        userRepository.save(user);
    }

    @Transactional
    public void triggerAdminApproval(User user) {
        String approvalString = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        ApprovalRequest approvalRequest = new ApprovalRequest();
        approvalRequest.setUserId(user.getId().toString());
        approvalRequest.setEmail(user.getEmail());
        approvalRequest.setRole(user.getRole());
        approvalRequest.setApprovalString(approvalString);
        approvalRequestRepository.save(approvalRequest);

        String encryptedId = user.getId().toString();

        emailService.sendApprovalRequest(superAdminEmail, encryptedId, approvalString,
                user.getEmail(), user.getRole());
    }
}