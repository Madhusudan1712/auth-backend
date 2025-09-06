package com.authcenter.auth_backend.dto.request;

import com.authcenter.auth_backend.model.Role;

public class UserExistsRequest {
    private String email;
    private String redirect;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getRedirect() {
        return redirect;
    }

    public void setRedirect(String redirect) {
        this.redirect = redirect;
    }
}
