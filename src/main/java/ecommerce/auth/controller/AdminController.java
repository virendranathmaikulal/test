package com.ecommerce.auth.controller;

import com.ecommerce.auth.dto.request.RoleUpdateRequest;
import com.ecommerce.auth.dto.response.ApiResponse;
import com.ecommerce.auth.dto.response.UserResponse;
import com.ecommerce.auth.service.AdminService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final AdminService adminService;

    @GetMapping("/users")
    public ResponseEntity<ApiResponse<List<UserResponse>>> getAllUsers() {
        List<UserResponse> users = adminService.getAllUsers();
        return ResponseEntity.ok(ApiResponse.success("Users retrieved", users));
    }

    @GetMapping("/users/{userId}")
    public ResponseEntity<ApiResponse<UserResponse>> getUser(@PathVariable UUID userId) {
        UserResponse user = adminService.getUserById(userId);
        return ResponseEntity.ok(ApiResponse.success("User retrieved", user));
    }

    @PostMapping("/users/{userId}/roles")
    public ResponseEntity<ApiResponse<UserResponse>> addRole(
            @PathVariable UUID userId,
            @Valid @RequestBody RoleUpdateRequest request) {
        UserResponse user = adminService.addRoleToUser(userId, request.getRoleName());
        return ResponseEntity.ok(ApiResponse.success("Role added successfully", user));
    }

    @DeleteMapping("/users/{userId}/roles")
    public ResponseEntity<ApiResponse<UserResponse>> removeRole(
            @PathVariable UUID userId,
            @Valid @RequestBody RoleUpdateRequest request) {
        UserResponse user = adminService.removeRoleFromUser(userId, request.getRoleName());
        return ResponseEntity.ok(ApiResponse.success("Role removed successfully", user));
    }

    @PostMapping("/users/{userId}/unlock")
    public ResponseEntity<ApiResponse<Void>> unlockUser(@PathVariable UUID userId) {
        adminService.unlockUser(userId);
        return ResponseEntity.ok(ApiResponse.success("Account unlocked successfully"));
    }
}
