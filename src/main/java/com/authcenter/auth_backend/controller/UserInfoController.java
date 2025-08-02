package com.authcenter.auth_backend.controller;

import com.authcenter.auth_backend.dto.response.ApiResponse;
import com.authcenter.auth_backend.model.User;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
public class UserInfoController {

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@AuthenticationPrincipal User user) {
        if (user == null) {
            return ResponseEntity.status(401).body(new ApiResponse<>("Unauthorized", null, 401));
        }

        return ResponseEntity.ok(new ApiResponse<>("Authenticated user", user, 200));
    }
}
