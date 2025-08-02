package com.authcenter.auth_backend.controller;

import com.authcenter.auth_backend.dto.response.ApiResponse;
import com.authcenter.auth_backend.model.ApprovalRequest;
import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.repository.ApprovalRequestRepository;
import com.authcenter.auth_backend.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/approval")
public class ApprovalController {

    private final ApprovalRequestRepository approvalRequestRepository;
    private final UserRepository userRepository;

    public ApprovalController(ApprovalRequestRepository approvalRequestRepository, UserRepository userRepository) {
        this.approvalRequestRepository = approvalRequestRepository;
        this.userRepository = userRepository;
    }

    @PostMapping("/approve")
    public ResponseEntity<?> approveUser(@RequestParam("userId") String userId,
                                         @RequestParam("approvalString") String approvalString) {

        Optional<ApprovalRequest> requestOpt = approvalRequestRepository.findByApprovalString(approvalString);
        if (requestOpt.isEmpty() || !requestOpt.get().getUserId().equals(userId)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>("Invalid approval string or user", null, 404));
        }

        ApprovalRequest request = requestOpt.get();
        if (request.isApproved() || request.isRejected()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse<>("Request already processed", null, 400));
        }

        Optional<User> userOpt = userRepository.findById(java.util.UUID.fromString(userId));
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>("User not found", null, 404));
        }

        User user = userOpt.get();
        user.setApproved(true);
        userRepository.save(user);

        request.setApproved(true);
        approvalRequestRepository.save(request);

        return ResponseEntity.ok(new ApiResponse<>("User approved successfully", null, 200));
    }

    @PostMapping("/reject")
    public ResponseEntity<?> rejectUser(@RequestParam("userId") String userId,
                                        @RequestParam("approvalString") String approvalString) {

        Optional<ApprovalRequest> requestOpt = approvalRequestRepository.findByApprovalString(approvalString);
        if (requestOpt.isEmpty() || !requestOpt.get().getUserId().equals(userId)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>("Invalid approval string or user", null, 404));
        }

        ApprovalRequest request = requestOpt.get();
        if (request.isApproved() || request.isRejected()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse<>("Request already processed", null, 400));
        }

        Optional<User> userOpt = userRepository.findById(java.util.UUID.fromString(userId));
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ApiResponse<>("User not found", null, 404));
        }

        // Optional: Delete or deactivate user
        userRepository.delete(userOpt.get());

        request.setRejected(true);
        approvalRequestRepository.save(request);

        return ResponseEntity.ok(new ApiResponse<>("User rejected and deleted successfully", null, 200));
    }
}