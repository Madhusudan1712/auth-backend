package com.authcenter.auth_backend.service;

import com.authcenter.auth_backend.dto.response.ApprovalRequestsResponse;
import jakarta.servlet.http.HttpServletRequest;

public interface ApprovalService {
    ApprovalRequestsResponse getApprovalRequests(HttpServletRequest request);
}
