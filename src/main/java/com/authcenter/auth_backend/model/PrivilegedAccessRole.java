package com.authcenter.auth_backend.model;

public enum PrivilegedAccessRole {
    ADMIN("Admin"),
    DEVELOPER("Developer"),
    MANAGER("Manager");

    private final String displayName;

    PrivilegedAccessRole(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
