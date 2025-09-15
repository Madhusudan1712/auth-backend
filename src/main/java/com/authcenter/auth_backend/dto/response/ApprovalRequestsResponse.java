package com.authcenter.auth_backend.dto.response;

import java.util.List;

public class ApprovalRequestsResponse {
    private List<ApplicationApproval> applications;

    public ApprovalRequestsResponse() {
    }

    public ApprovalRequestsResponse(List<ApplicationApproval> applications) {
        this.applications = applications;
    }

    public List<ApplicationApproval> getApplications() {
        return applications;
    }

    public void setApplications(List<ApplicationApproval> applications) {
        this.applications = applications;
    }
}
