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

/**
 * Core authentication service — handles login, refresh, and logout.
 *
 * Design decisions:
 * - login() is NOT @Transactional — DB writes and Redis writes are independent failure domains.
 *   handleFailedLogin() and resetFailedAttemptsIfNeeded() have their own @Transactional.
 * - Manual password check (not AuthenticationManager) — needed to track failed attempts per user.
 * - Same error message for "email not found" and "wrong password" — prevents email enumeration.
 */
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
     * Login flow per BRD 5.2. Returns access token (15min) + refresh token (7 days).
     * Checks: email exists → account active → not locked → password matches.
     * On failure: increments counter, locks at 3 attempts.
     */
    public LoginResponse login(LoginRequest request) {
        // Same error for "not found" and "wrong password" — anti-enumeration
        User user = userRepository.findByEmail(request.getEmail().toLowerCase().trim())
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        // Check account lifecycle status (ACTIVE/INACTIVE/SUSPENDED)
        if (!AuthConstants.STATUS_ACTIVE.equals(user.getStatus())) {
            throw new BadRequestException("Account is not active. Current status: " + user.getStatus());
        }

        // Check account lock (set after MAX_FAILED_LOGIN_ATTEMPTS wrong passwords)
        if (user.isAccountLocked()) {
            throw new AccountLockedException(
                    "Account is locked due to too many failed login attempts. Please reset your password to unlock.");
        }

        // BCrypt.matches() — intentionally slow (~250ms at strength 12). This IS the security.
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            handleFailedLogin(user); // Separate @Transactional — persists even if Redis fails later
            throw new BadCredentialsException("Invalid email or password");
        }

        // Success — reset counter (only writes to DB if counter > 0)
        resetFailedAttemptsIfNeeded(user);

        // Generate both tokens and store in Redis (outside DB transaction)
        return generateTokenPair(user);
    }

    /**
     * Refresh token rotation per OAuth2 best practices.
     * Old refresh token is deleted (one-time use). New pair issued.
     * Re-checks account status — a suspended user can't refresh.
     * Loads fresh roles from DB — role changes take effect on refresh.
     */
    public LoginResponse refresh(RefreshTokenRequest request) {
        UUID userId = tokenService.validateRefreshToken(request.getRefreshToken());
        if (userId == null) {
            throw new TokenException("Invalid or expired refresh token");
        }

        // Delete old token BEFORE issuing new one — prevents reuse if this call fails midway
        tokenService.deleteRefreshToken(request.getRefreshToken());

        // Fresh DB read — picks up any role changes since last login
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new TokenException("User not found for refresh token"));

        // Re-validate account state — user could have been locked/deactivated since login
        if (!AuthConstants.STATUS_ACTIVE.equals(user.getStatus())) {
            throw new BadRequestException("Account is not active");
        }
        if (user.isAccountLocked()) {
            throw new AccountLockedException("Account is locked");
        }

        log.info("Token refreshed for user: {}", user.getEmail());
        return generateTokenPair(user);
    }

    /** Revoke access token + optionally refresh token. Both removed from Redis. */
    public void logout(UUID userId, String refreshToken) {
        tokenService.revokeAccessToken(userId);
        if (refreshToken != null) {
            tokenService.deleteRefreshToken(refreshToken);
        }
        log.info("User logged out: {}", userId);
    }

    /**
     * Generate access + refresh token pair and store both in Redis.
     * Access token: JWT with embedded claims (userId, email, roles). Short-lived.
     * Refresh token: opaque SecureRandom string. Long-lived. No claims — just a Redis key.
     */
    private LoginResponse generateTokenPair(User user) {
        List<String> roles = user.getRoles().stream()
                .map(role -> role.getRoleName().name())
                .toList();

        String accessToken = jwtProvider.generateToken(user.getUserId(), user.getEmail(), roles);
        tokenService.storeAccessToken(user.getUserId(), accessToken, jwtProvider.getExpirationMs());

        String refreshToken = tokenService.generateAndStoreRefreshToken(
                user.getUserId(), refreshTokenExpirationMs);

        return LoginResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(jwtProvider.getExpirationMs() / 1000) // Convert ms → seconds for client
                .build();
    }

    /**
     * Separate @Transactional — failed attempt counter persists independently of Redis operations.
     * If Redis fails after this, the counter is still incremented (security-critical).
     */
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

    /** Only writes to DB if counter > 0 — avoids unnecessary DB writes on every successful login. */
    @Transactional
    protected void resetFailedAttemptsIfNeeded(User user) {
        if (user.getFailedLoginAttempts() > 0) {
            user.setFailedLoginAttempts(0);
            userRepository.save(user);
        }
    }
}
