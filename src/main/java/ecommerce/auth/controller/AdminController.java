package com.ecommerce.auth.controller;

import com.ecommerce.auth.dto.request.RoleUpdateRequest;
import com.ecommerce.auth.dto.response.ApiResponse;
import com.ecommerce.auth.dto.response.UserResponse;
import com.ecommerce.auth.service.AdminService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final AdminService adminService;

    @GetMapping("/users")
    public ResponseEntity<ApiResponse<Page<UserResponse>>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Page<UserResponse> users = adminService.getAllUsers(page, size);
        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, "Users retrieved", users));
    }

    @GetMapping("/users/{userId}")
    public ResponseEntity<ApiResponse<UserResponse>> getUser(@PathVariable UUID userId) {
        UserResponse user = adminService.getUserById(userId);
        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, "User retrieved", user));
    }

    @PostMapping("/users/{userId}/roles")
    public ResponseEntity<ApiResponse<UserResponse>> addRole(
            @PathVariable UUID userId,
            @Valid @RequestBody RoleUpdateRequest request) {
        UserResponse user = adminService.addRoleToUser(userId, request.getRoleName());
        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, "Role added successfully", user));
    }

    /**
     * Uses @RequestParam instead of @RequestBody for DELETE.
     * Many HTTP clients and proxies strip the body from DELETE requests.
     */
    @DeleteMapping("/users/{userId}/roles/{roleName}")
    public ResponseEntity<ApiResponse<UserResponse>> removeRole(
            @PathVariable UUID userId,
            @PathVariable String roleName) {
        UserResponse user = adminService.removeRoleFromUser(userId, roleName);
        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, "Role removed successfully", user));
    }

    @PostMapping("/users/{userId}/unlock")
    public ResponseEntity<ApiResponse<Void>> unlockUser(@PathVariable UUID userId) {
        adminService.unlockUser(userId);
        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, "Account unlocked successfully"));
    }
}
