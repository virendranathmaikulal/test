
package com.ecommerce.auth.controller;

import com.ecommerce.auth.dto.request.LoginRequest;
import com.ecommerce.auth.dto.response.ApiResponse;
import com.ecommerce.auth.dto.response.LoginResponse;
import com.ecommerce.auth.dto.response.TokenValidationResponse;
import com.ecommerce.auth.security.JwtProvider;
import com.ecommerce.auth.service.AuthService;
import com.ecommerce.auth.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtProvider jwtProvider;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest request) {
        LoginResponse response = authService.login(request);
        return ResponseEntity.ok(ApiResponse.success("Login successful", response));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(HttpServletRequest request) {
        String token = extractToken(request);
        UUID userId = jwtProvider.getUserIdFromToken(token);
        authService.logout(userId);
        return ResponseEntity.ok(ApiResponse.success("Logged out successfully"));
    }

    /**
     * Token validation endpoint for downstream microservices.
     * Other services call this to verify a user's token without needing the JWT secret.
     */
    @GetMapping("/auth/validate")
    public ResponseEntity<ApiResponse<TokenValidationResponse>> validateToken(HttpServletRequest request) {
        String token = extractToken(request);

        if (!jwtProvider.validateToken(token)) {
            return ResponseEntity.ok(ApiResponse.success("Token invalid",
                    TokenValidationResponse.builder().valid(false).build()));
        }

        UUID userId = jwtProvider.getUserIdFromToken(token);

        if (!tokenService.isTokenValid(userId, token)) {
            return ResponseEntity.ok(ApiResponse.success("Token revoked",
                    TokenValidationResponse.builder().valid(false).build()));
        }

        List<String> roles = jwtProvider.getRolesFromToken(token);
        String email = jwtProvider.parseToken(token).get("email", String.class);

        return ResponseEntity.ok(ApiResponse.success("Token valid",
                TokenValidationResponse.builder()
                        .valid(true)
                        .userId(userId)
                        .email(email)
                        .roles(roles)
                        .build()));
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        throw new IllegalArgumentException("Missing or invalid Authorization header");
    }
}
