package com.authcenter.auth_backend.dto.response;

import java.util.List;

public class ApplicationApproval {

    private String application;
    private List<PendingUser> pendingUsers;

    public ApplicationApproval() {
    }

    public ApplicationApproval(String application, List<PendingUser> pendingUsers) {
        this.application = application;
        this.pendingUsers = pendingUsers;
    }

    public String getApplication() {
        return application;
    }

    public void setApplication(String application) {
        this.application = application;
    }

    public List<PendingUser> getPendingUsers() {
        return pendingUsers;
    }

    public void setPendingUsers(List<PendingUser> pendingUsers) {
        this.pendingUsers = pendingUsers;
    }
}
