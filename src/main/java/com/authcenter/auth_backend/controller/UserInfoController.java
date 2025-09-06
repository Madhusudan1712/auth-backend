package com.authcenter.auth_backend.controller;

import com.authcenter.auth_backend.dto.response.ApiResponse;
import com.authcenter.auth_backend.dto.response.UserDto;
import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.repository.UserRepository;
import com.authcenter.auth_backend.security.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.Optional;

@RestController
@RequestMapping("/user")
public class UserInfoController {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    public UserInfoController(JwtService jwtService, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(HttpServletRequest request) {
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
                    .body(new ApiResponse<>("Unauthorized", null, 401));
        }

        // 2. Extract email + application from JWT
        String email = jwtService.extractEmail(token);
        String application = jwtService.extractClaim(token, claims -> (String) claims.get("application"));

        // 3. Lookup user by email + application
        Optional<User> userOpt = userRepository.findByEmailAndApplication(email, application);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>("User not found", null, 404));
        }

        // 4. Convert to DTO
        UserDto userDto = new UserDto(userOpt.get());

        return ResponseEntity.ok(new ApiResponse<>("Authenticated user", userDto, 200));
    }
}
