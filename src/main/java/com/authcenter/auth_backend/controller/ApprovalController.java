package com.authcenter.auth_backend.controller;

import com.authcenter.auth_backend.dto.request.ApproveRejectRequest;
import com.authcenter.auth_backend.dto.response.ApiResponse;
import com.authcenter.auth_backend.dto.response.ApprovalRequestsResponse;
import com.authcenter.auth_backend.model.Status;
import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.model.UserRole;
import com.authcenter.auth_backend.repository.UserRepository;
import com.authcenter.auth_backend.repository.UserRoleRepository;
import com.authcenter.auth_backend.service.ApprovalService;
import com.authcenter.auth_backend.service.EmailService;
import com.authcenter.auth_backend.service.UserRoleService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/approval")
public class ApprovalController {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final UserRoleService userRoleService;
    private final EmailService emailService;
    private final ApprovalService approvalService;

    public ApprovalController(UserRepository userRepository, UserRoleRepository userRoleRepository, UserRoleService userRoleService, EmailService emailService, ApprovalService approvalService) {
        this.userRepository = userRepository;
        this.userRoleRepository = userRoleRepository;
        this.userRoleService = userRoleService;
        this.emailService = emailService;
        this.approvalService = approvalService;
    }

    @GetMapping("/approvals/pending")
    public ResponseEntity<ApiResponse<ApprovalRequestsResponse>> getApprovalRequests(HttpServletRequest request) {
        ApprovalRequestsResponse result = approvalService.getApprovalRequests(request);
        if(result == null) {
            return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
        }
        return ResponseEntity.ok(new ApiResponse<>("Pending approvals", result, 200));
    }

    @PostMapping("/approve")
    public ResponseEntity<?> approveUser(@RequestBody ApproveRejectRequest req) {

        Optional<User> userOpt = userRepository.findById(java.util.UUID.fromString(req.getUserId()));

        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>("User not found", null, 404));
        }

        User user = userOpt.get();

        Optional<UserRole> requestOpt = userRoleRepository.findByApprovalString(req.getApprovalString());

        if (requestOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>("Approval request expired", null, 404));
        }

        UserRole request = requestOpt.get();
        if (request.isApproved() || request.isRejected()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse<>("Request already processed", null, 400));
        }

        if (!requestOpt.get().getUser().equals(user)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>("Invalid approval string or user", null, 404));
        }

        List<UserRole> userRoles = userRoleRepository.findAllByUser(user);
        for (UserRole userRole : userRoles) {
            String currentRole = userRole.getRole().toString().toUpperCase();
            if(currentRole.equals(req.getRole())) {
                userRole.setApproved(true);
                userRole.setRejected(false);
                userRole.setApprovalString(null);
                userRoleService.save(userRole);
            }
        }

        emailService.sendApprovedOrRejectedEmail(userOpt.get().getEmail(), userOpt.get().getApplication(), Status.APPROVED, req.getReason());
        return ResponseEntity.ok(new ApiResponse<>("User approved successfully", null, 200));
    }

    @PostMapping("/reject")
    public ResponseEntity<?> rejectUser(@RequestBody ApproveRejectRequest req) {

        Optional<User> userOpt = userRepository.findById(java.util.UUID.fromString(req.getUserId()));

        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>("User not found", null, 404));
        }

        User user = userOpt.get();

        Optional<UserRole> requestOpt = userRoleRepository.findByApprovalString(req.getApprovalString());

        if (requestOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>("Approval request expired", null, 404));
        }

        UserRole request = requestOpt.get();
        if (request.isApproved() || request.isRejected()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse<>("Request already processed", null, 400));
        }

        if (!requestOpt.get().getUser().equals(user)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>("Invalid approval string or user", null, 404));
        }

        List<UserRole> userRoles = userRoleRepository.findAllByUser(user);
        for (UserRole userRole : userRoles) {
            String currentRole = userRole.getRole().toString().toUpperCase();
            if(currentRole.equals(req.getRole())) {
                userRole.setApproved(false);
                userRole.setRejected(true);
                userRole.setApprovalString(null);
                userRoleService.save(userRole);
            }
        }

        emailService.sendApprovedOrRejectedEmail(userOpt.get().getEmail(), userOpt.get().getApplication(), Status.REJECTED, req.getReason());
        return ResponseEntity.ok(new ApiResponse<>("User rejected successfully", null, 200));
    }
}