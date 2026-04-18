package com.ecommerce.auth.controller;

import com.ecommerce.auth.dto.request.ForgotPasswordRequest;
import com.ecommerce.auth.dto.request.RegisterRequest;
import com.ecommerce.auth.dto.request.ResetPasswordRequest;
import com.ecommerce.auth.dto.response.ApiResponse;
import com.ecommerce.auth.dto.response.UserResponse;
import com.ecommerce.auth.service.PasswordService;
import com.ecommerce.auth.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;

@RestController
@RequestMapping("/api/v1/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final PasswordService passwordService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<UserResponse>> register(@Valid @RequestBody RegisterRequest request) {
        UserResponse user = userService.register(request);

        URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath()
                .path("/api/v1/admin/users/{userId}")
                .buildAndExpand(user.getUserId())
                .toUri();

        return ResponseEntity
                .created(location)
                .body(ApiResponse.success(HttpStatus.CREATED, "User registered successfully", user));
    }

    @PostMapping("/forgot_password")
    public ResponseEntity<ApiResponse<Void>> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        passwordService.forgotPassword(request);
        return ResponseEntity.ok(
                ApiResponse.success(HttpStatus.OK, "If the email exists, a reset link has been sent"));
    }

    @PostMapping("/reset_password")
    public ResponseEntity<ApiResponse<Void>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        passwordService.resetPassword(request);
        return ResponseEntity.ok(
                ApiResponse.success(HttpStatus.OK, "Password reset successfully. Please login with your new password."));
    }
}
