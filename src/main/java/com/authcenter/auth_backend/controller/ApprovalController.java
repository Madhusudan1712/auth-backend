package com.authcenter.auth_backend.controller;

import com.authcenter.auth_backend.dto.request.ApproveRejectRequest;
import com.authcenter.auth_backend.dto.response.ApiResponse;
import com.authcenter.auth_backend.dto.response.ApprovalRequestsResponse;
import com.authcenter.auth_backend.dto.response.UserDto;
import com.authcenter.auth_backend.model.Status;
import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.model.UserRole;
import com.authcenter.auth_backend.repository.UserRepository;
import com.authcenter.auth_backend.repository.UserRoleRepository;
import com.authcenter.auth_backend.security.JwtService;
import com.authcenter.auth_backend.service.ApprovalService;
import com.authcenter.auth_backend.service.EmailService;
import com.authcenter.auth_backend.service.UserRoleService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/approval")
public class ApprovalController {

    @Value("${authcenter.super.admin.email}")
    private String superAdminEmail;

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final UserRoleService userRoleService;
    private final EmailService emailService;
    private final ApprovalService approvalService;

    public ApprovalController(JwtService jwtService, UserRepository userRepository, UserRoleRepository userRoleRepository, UserRoleService userRoleService, EmailService emailService, ApprovalService approvalService) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.userRoleRepository = userRoleRepository;
        this.userRoleService = userRoleService;
        this.emailService = emailService;
        this.approvalService = approvalService;
    }

    @GetMapping("/is-super-admin")
    public ResponseEntity<ApiResponse<Boolean>> isSuperAdmin(HttpServletRequest request) {
        // 1. Extract JWT from cookie
        String token = Arrays.stream(
                        Optional.ofNullable(request.getCookies()).orElse(new Cookie[0])
                )
                .filter(c -> "auth_token".equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);

        if (token == null || !jwtService.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>("Invalid or missing token", null, 401));
        }

        // 2. Check if super admin
        boolean isSuperAdmin = approvalService.isSuperAdmin(token);
        
        return ResponseEntity.ok(new ApiResponse<>(
                isSuperAdmin ? "Authenticated super admin" : "Not a super admin", 
                isSuperAdmin, 
                200
        ));
    }

    @GetMapping("/pending")
    public ResponseEntity<ApiResponse<ApprovalRequestsResponse>> getApprovalRequests(HttpServletRequest request) {
        // 1. Extract JWT
        String token = Arrays.stream(
                        Optional.ofNullable(request.getCookies()).orElse(new Cookie[0])
                )
                .filter(c -> "auth_token".equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);

        if (token == null || !jwtService.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>("Unauthorized", null, 401));
        }

        // 2. Check if super admin
        if (!approvalService.isSuperAdmin(token)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>("Not a super admin", null, 403));
        }

        // 5. Fetch approvals
        ApprovalRequestsResponse result = approvalService.getApprovalRequests(request);
        if (result == null) {
            return ResponseEntity.status(HttpStatus.NO_CONTENT)
                    .body(new ApiResponse<>("No pending approvals", null, 204));
        }

        return ResponseEntity.ok(new ApiResponse<>("Pending approvals", result, 200));
    }

    @PostMapping("/approve")
    public ResponseEntity<?> approveUser(@RequestBody ApproveRejectRequest req, HttpServletRequest request) {
        // 1. Extract JWT from cookie
        String token = Arrays.stream(
                        Optional.ofNullable(request.getCookies()).orElse(new Cookie[0])
                )
                .filter(c -> "auth_token".equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);

        if (token == null || !jwtService.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>("Invalid or missing token", null, 401));
        }

        // 2. Check if super admin
        boolean isSuperAdmin = approvalService.isSuperAdmin(token);
        if (!isSuperAdmin) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>("Not a super admin", null, 403));
        }

        // 3. Find the user
        Optional<User> userOpt = userRepository.findById(java.util.UUID.fromString(req.getUserId()));
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>("User not found", null, 404));
        }

        User user = userOpt.get();
        List<UserRole> userRoles = userRoleRepository.findAllByUser(user);
        
        // 4. Check if the role exists and its status
        boolean roleFound = false;
        for (UserRole userRole : userRoles) {
            String currentRole = userRole.getRole().toString().toUpperCase();
            if (currentRole.equals(req.getRole().toUpperCase())) {
                roleFound = true;
                
                // Check if already approved or rejected
                if (userRole.isApproved()) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(new ApiResponse<>("Role already approved for this user", null, 400));
                }
                
                if (userRole.isRejected()) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(new ApiResponse<>("Role already rejected for this user", null, 400));
                }
                break;
            }
        }
        
        if (!roleFound) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>("Role not found for this user", null, 404));
        }
        
        // 5. Process the approval for the specific role
        for (UserRole userRole : userRoles) {
            String currentRole = userRole.getRole().toString().toUpperCase();
            if (currentRole.equals(req.getRole().toUpperCase())) {
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
    public ResponseEntity<?> rejectUser(@RequestBody ApproveRejectRequest req, HttpServletRequest httpRequest) {
        // 1. Extract JWT from cookie
        String token = Arrays.stream(
                        Optional.ofNullable(httpRequest.getCookies()).orElse(new Cookie[0])
                )
                .filter(c -> "auth_token".equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);

        if (token == null || !jwtService.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>("Invalid or missing token", null, 401));
        }

        // 2. Check if super admin
        boolean isSuperAdmin = approvalService.isSuperAdmin(token);
        if (!isSuperAdmin) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse<>("Not a super admin", null, 403));
        }

        // 3. Find the user
        Optional<User> userOpt = userRepository.findById(java.util.UUID.fromString(req.getUserId()));
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>("User not found", null, 404));
        }

        User user = userOpt.get();
        List<UserRole> userRoles = userRoleRepository.findAllByUser(user);
        
        // 4. Check if the role exists and its status
        boolean roleFound = false;
        for (UserRole userRole : userRoles) {
            String currentRole = userRole.getRole().toString().toUpperCase();
            if (currentRole.equals(req.getRole().toUpperCase())) {
                roleFound = true;
                
                // Check if already approved or rejected
                if (userRole.isApproved()) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(new ApiResponse<>("Role already approved for this user", null, 400));
                }
                
                if (userRole.isRejected()) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(new ApiResponse<>("Role already rejected for this user", null, 400));
                }
                
                // If we get here, the role exists and is not yet processed
                break;
            }
        }
        
        if (!roleFound) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>("Role not found for this user", null, 404));
        }
        
        // 5. Process the rejection for the specific role
        for (UserRole userRole : userRoles) {
            String currentRole = userRole.getRole().toString().toUpperCase();
            if (currentRole.equals(req.getRole().toUpperCase())) {
                userRole.setApproved(false);
                userRole.setRejected(true);
                userRole.setApprovalString(null);
                userRoleService.save(userRole);
            }
        }

        emailService.sendApprovedOrRejectedEmail(user.getEmail(), user.getApplication(), Status.REJECTED, req.getReason());
        return ResponseEntity.ok(new ApiResponse<>("User rejected successfully", null, 200));
    }
}