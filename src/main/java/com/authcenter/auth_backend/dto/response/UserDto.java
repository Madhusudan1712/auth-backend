package com.authcenter.auth_backend.dto.response;

import com.authcenter.auth_backend.model.Role;
import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.model.UserRole;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class UserDto {
    private final UUID id;
    private final String name;
    private final String email;
    private final Set<String> roles;  // now supports multiple roles
    private final String application;
    private final boolean mfaEnabled;
    private final boolean mfaBypassed;

    // Constructor
    public UserDto(User user) {
        this.id = user.getId();
        this.name = user.getName();
        this.email = user.getEmail();
        this.roles = user.getRoles()
                .stream()
                .filter(UserRole::isApproved) //Only includes approved roles
                .map(UserRole::getRole)
                .map(Role::name)
                .collect(Collectors.toSet());
        this.application = user.getApplication();
        this.mfaEnabled = user.isMfaEnabled();
        this.mfaBypassed = user.isMfaBypassed();
    }

    // Getters
    public UUID getId() { return id; }
    public String getName() { return name; }
    public String getEmail() { return email; }
    public Set<String> getRoles() { return roles; }
    public String getApplication() { return application; }
    public boolean isMfaEnabled() { return mfaEnabled; }
    public boolean isMfaBypassed() { return mfaBypassed; }
}
