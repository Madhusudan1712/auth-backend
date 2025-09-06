package com.authcenter.auth_backend.model;

import jakarta.persistence.*;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "users")
public class User extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    private String name;
    private String email;
    private String password;
    private String application;

    private boolean mfaEnabled = false;
    private String mfaSecret;
    private boolean mfaBypassed = false;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    private Set<UserRole> roles = new HashSet<>();

    // Convenience method
    public void addRole(Role role, String approvalString, Status status) {
        boolean alreadyExists = this.roles.stream()
                .anyMatch(r -> r.getRole() == role);

        if (alreadyExists) {
            return; // Prevent duplicate role insertions
        }

        UserRole ur = new UserRole();
        ur.setUser(this);
        ur.setRole(role);
        ur.setApprovalString(approvalString);
        ur.setApproved(status == Status.APPROVED);
        ur.setRejected(status == Status.REJECTED);
        this.roles.add(ur);
    }

    // Getters and setters
    public UUID getId() {
        return id;
    }
    public void setId(UUID id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }
    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }

    public String getApplication() {
        return application;
    }
    public void setApplication(String application) {
        this.application = application;
    }

    public boolean isMfaEnabled() {
        return mfaEnabled;
    }
    public void setMfaEnabled(boolean mfaEnabled) {
        this.mfaEnabled = mfaEnabled;
    }

    public String getMfaSecret() {
        return mfaSecret;
    }
    public void setMfaSecret(String mfaSecret) {
        this.mfaSecret = mfaSecret;
    }

    public boolean isMfaBypassed() {
        return mfaBypassed;
    }
    public void setMfaBypassed(boolean mfaBypassed) {
        this.mfaBypassed = mfaBypassed;
    }

    public Set<UserRole> getRoles() {
        return roles;
    }
    public void setRoles(Set<UserRole> roles) {
        this.roles = roles;
    }
}
