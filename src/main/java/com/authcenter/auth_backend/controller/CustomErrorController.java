package com.authcenter.auth_backend.controller;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
public class CustomErrorController implements ErrorController {

    @RequestMapping("/error")
    public ResponseEntity<Map<String, Object>> handleError(HttpServletRequest request) {
        Object status = request.getAttribute("jakarta.servlet.error.status_code");
        Object message = request.getAttribute("jakarta.servlet.error.message");
        Object exception = request.getAttribute("jakarta.servlet.error.exception");

        int statusCode = status != null ? Integer.parseInt(status.toString()) : 500;

        System.err.println("⚠️ OAuth Error: " + message);

        // ✅ Cast to Throwable before calling printStackTrace
        if (exception instanceof Throwable) {
            ((Throwable) exception).printStackTrace();
        }

        return ResponseEntity.status(statusCode).body(Map.of(
                "message", "Something went wrong during authentication",
                "details", message != null ? message : "Unknown error",
                "statusCode", statusCode
        ));
    }
}
