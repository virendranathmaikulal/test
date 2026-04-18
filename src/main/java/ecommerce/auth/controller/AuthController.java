package com.ecommerce.auth.controller;

import com.ecommerce.auth.constants.AuthConstants;
import com.ecommerce.auth.dto.request.LoginRequest;
import com.ecommerce.auth.dto.response.ApiResponse;
import com.ecommerce.auth.dto.response.LoginResponse;
import com.ecommerce.auth.dto.response.TokenValidationResponse;
import com.ecommerce.auth.exception.TokenException;
import com.ecommerce.auth.security.JwtProvider;
import com.ecommerce.auth.service.AuthService;
import com.ecommerce.auth.service.TokenService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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
        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, "Login successful", response));
    }

    /**
     * Logout per BRD 5.3:
     * - Extract JWT from request
     * - Remove token from Redis
     * - Session is invalidated
     *
     * Uses @AuthenticationPrincipal to get userId from SecurityContext
     * (already parsed and validated by JwtAuthenticationFilter — no re-parse needed).
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@AuthenticationPrincipal UUID userId) {
        authService.logout(userId);
        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, "Logged out successfully"));
    }

    /**
     * Token validation endpoint for downstream microservices (BRD 5.4).
     * Other services call this to verify a user's token without needing the JWT secret.
     * Single-parse approach for performance.
     */
    @GetMapping("/auth/validate")
    public ResponseEntity<ApiResponse<TokenValidationResponse>> validateToken(HttpServletRequest request) {
        String token = extractTokenOrThrow(request);

        // Single parse — signature + expiration check
        Claims claims = jwtProvider.parseTokenSafe(token);
        if (claims == null) {
            return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, "Token invalid",
                    TokenValidationResponse.builder().valid(false).build()));
        }

        UUID userId = jwtProvider.getUserIdFromClaims(claims);

        // Redis revocation check
        if (!tokenService.isTokenValid(userId, token)) {
            return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, "Token revoked",
                    TokenValidationResponse.builder().valid(false).build()));
        }

        List<String> roles = jwtProvider.getRolesFromClaims(claims);
        String email = jwtProvider.getEmailFromClaims(claims);

        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, "Token valid",
                TokenValidationResponse.builder()
                        .valid(true)
                        .userId(userId)
                        .email(email)
                        .roles(roles)
                        .build()));
    }

    private String extractTokenOrThrow(HttpServletRequest request) {
        String header = request.getHeader(AuthConstants.AUTH_HEADER);
        if (header != null && header.startsWith(AuthConstants.BEARER_PREFIX)) {
            return header.substring(AuthConstants.BEARER_PREFIX.length());
        }
        throw new TokenException("Missing or invalid Authorization header");
    }
}
