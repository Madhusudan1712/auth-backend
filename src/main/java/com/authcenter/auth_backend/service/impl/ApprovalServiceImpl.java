package com.authcenter.auth_backend.service.impl;

import com.authcenter.auth_backend.dto.response.ApprovalRequestsResponse;
import com.authcenter.auth_backend.dto.response.ApplicationApproval;
import com.authcenter.auth_backend.dto.response.PendingUser;
import com.authcenter.auth_backend.model.Role;
import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.model.UserRole;
import com.authcenter.auth_backend.repository.UserRoleRepository;
import com.authcenter.auth_backend.service.ApprovalService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class ApprovalServiceImpl implements ApprovalService {

    private final UserRoleRepository userRoleRepository;

    @Autowired
    public ApprovalServiceImpl(UserRoleRepository userRoleRepository) {
        this.userRoleRepository = userRoleRepository;
    }

    @Override
    public ApprovalRequestsResponse getApprovalRequests(HttpServletRequest request) {
        // Find all user roles that are neither approved nor rejected
        List<UserRole> pendingApprovals = userRoleRepository.findByApprovedFalseAndRejectedFalse();
        
        // Group by application name
        Map<String, List<UserRole>> approvalsByApplication = pendingApprovals.stream()
                .collect(Collectors.groupingBy(
                        userRole -> userRole.getUser().getApplication()
                ));
        
        // Convert to response DTOs and sort by application name
        List<ApplicationApproval> applicationApprovals = approvalsByApplication.entrySet().stream()
                .map(entry -> {
                    String application = entry.getKey();
                    List<PendingUser> pendingUsers = entry.getValue().stream()
                            .map(userRole -> {
                                User user = userRole.getUser();
                                return new PendingUser(
                                    user.getId().toString(),
                                    user.getEmail(),
                                    userRole.getRole().name()
                                );
                            })
                            .sorted((u1, u2) -> u1.getEmail().compareToIgnoreCase(u2.getEmail()))
                            .collect(Collectors.toList());
                    
                    return new ApplicationApproval(application, pendingUsers);
                })
                .sorted((a1, a2) -> a1.getApplication().compareToIgnoreCase(a2.getApplication()))
                .collect(Collectors.toList());
        
        return new ApprovalRequestsResponse(applicationApprovals);
    }
}
