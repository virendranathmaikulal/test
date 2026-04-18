package com.ecommerce.auth.service;

import com.ecommerce.auth.constants.AuthConstants;
import com.ecommerce.auth.dto.request.LoginRequest;
import com.ecommerce.auth.dto.request.RefreshTokenRequest;
import com.ecommerce.auth.dto.response.LoginResponse;
import com.ecommerce.auth.entity.User;
import com.ecommerce.auth.exception.AccountLockedException;
import com.ecommerce.auth.exception.BadRequestException;
import com.ecommerce.auth.exception.TokenException;
import com.ecommerce.auth.repository.UserRepository;
import com.ecommerce.auth.security.JwtProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtProvider jwtProvider;
    private final TokenService tokenService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.refresh-token.expiration-ms}")
    private long refreshTokenExpirationMs;

    /**
     * Login flow per BRD 5.2:
     * 1. Validate credentials
     * 2. Check account status + lock
     * 3. Generate access token (short-lived, 15 min)
     * 4. Generate refresh token (long-lived, 7 days)
     * 5. Store both in Redis
     * 6. Return both to client
     */
    public LoginResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail().toLowerCase().trim())
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        if (!AuthConstants.STATUS_ACTIVE.equals(user.getStatus())) {
            throw new BadRequestException("Account is not active. Current status: " + user.getStatus());
        }

        if (user.isAccountLocked()) {
            throw new AccountLockedException(
                    "Account is locked due to too many failed login attempts. Please reset your password to unlock.");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            handleFailedLogin(user);
            throw new BadCredentialsException("Invalid email or password");
        }

        resetFailedAttemptsIfNeeded(user);

        return generateTokenPair(user);
    }

    /**
     * Refresh flow:
     * 1. Validate refresh token in Redis
     * 2. Delete old refresh token (one-time use — rotation)
     * 3. Generate new access token + new refresh token
     * 4. Store both in Redis
     * 5. Return both to client
     */
    public LoginResponse refresh(RefreshTokenRequest request) {
        // Step 1: Validate refresh token
        UUID userId = tokenService.validateRefreshToken(request.getRefreshToken());
        if (userId == null) {
            throw new TokenException("Invalid or expired refresh token");
        }

        // Step 2: Delete old refresh token (rotation — prevents reuse)
        tokenService.deleteRefreshToken(request.getRefreshToken());

        // Step 3: Load user (need fresh roles — they may have changed since last login)
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new TokenException("User not found for refresh token"));

        // Step 4: Check account is still active and not locked
        if (!AuthConstants.STATUS_ACTIVE.equals(user.getStatus())) {
            throw new BadRequestException("Account is not active");
        }
        if (user.isAccountLocked()) {
            throw new AccountLockedException("Account is locked");
        }

        // Step 5: Generate new token pair
        log.info("Token refreshed for user: {}", user.getEmail());
        return generateTokenPair(user);
    }

    public void logout(UUID userId, String refreshToken) {
        tokenService.revokeAccessToken(userId);
        if (refreshToken != null) {
            tokenService.deleteRefreshToken(refreshToken);
        }
        log.info("User logged out: {}", userId);
    }

    // --- Private helpers ---

    private LoginResponse generateTokenPair(User user) {
        List<String> roles = user.getRoles().stream()
                .map(role -> role.getRoleName().name())
                .toList();

        // Access token (JWT, short-lived)
        String accessToken = jwtProvider.generateToken(user.getUserId(), user.getEmail(), roles);
        tokenService.storeAccessToken(user.getUserId(), accessToken, jwtProvider.getExpirationMs());

        // Refresh token (opaque, long-lived)
        String refreshToken = tokenService.generateAndStoreRefreshToken(
                user.getUserId(), refreshTokenExpirationMs);

        return LoginResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(jwtProvider.getExpirationMs() / 1000)
                .build();
    }

    @Transactional
    protected void handleFailedLogin(User user) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);

        if (attempts >= AuthConstants.MAX_FAILED_LOGIN_ATTEMPTS) {
            user.setAccountLocked(true);
            user.setLockedAt(Instant.now());
            log.warn("Account locked for user: {} after {} failed attempts", user.getEmail(), attempts);
        } else {
            log.info("Failed login attempt {} of {} for user: {}",
                    attempts, AuthConstants.MAX_FAILED_LOGIN_ATTEMPTS, user.getEmail());
        }

        userRepository.save(user);
    }

    @Transactional
    protected void resetFailedAttemptsIfNeeded(User user) {
        if (user.getFailedLoginAttempts() > 0) {
            user.setFailedLoginAttempts(0);
            userRepository.save(user);
        }
    }
}
