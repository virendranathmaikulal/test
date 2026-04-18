package com.ecommerce.auth.service;

import com.ecommerce.auth.dto.request.ForgotPasswordRequest;
import com.ecommerce.auth.dto.request.ResetPasswordRequest;
import com.ecommerce.auth.entity.User;
import com.ecommerce.auth.exception.BadRequestException;
import com.ecommerce.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

/**
 * Password recovery service — BRD Sections 5.5 and 5.6.
 *
 * Design decisions:
 * - forgotPassword() always returns success — prevents email enumeration attacks.
 * - Reset token uses SecureRandom (256 bits) not UUID (122 bits) — higher entropy.
 * - Email sending abstracted behind EmailService interface (Dependency Inversion).
 *   POC uses ConsoleEmailService. Production: swap to SES/SendGrid with @Primary.
 * - resetPassword() has 3 phases: Redis validate → DB update (transactional) → Redis cleanup.
 *   DB and Redis are separate failure domains — password change persists even if Redis hiccups.
 * - Reset also unlocks account — per updated requirement (locked user's recovery path).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int RESET_TOKEN_BYTES = 32; // 256 bits of entropy

    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService; // Interface — decoupled from implementation

    @Value("${app.password-reset.expiration-ms}")
    private long resetTokenExpirationMs;

    /**
     * BRD 5.5: Forgot password flow.
     * Always returns success regardless of email existence — anti-enumeration.
     * If email exists: generate token → store in Redis (15min TTL) → send email.
     */
    public void forgotPassword(ForgotPasswordRequest request) {
        String email = request.getEmail().toLowerCase().trim();

        userRepository.findByEmail(email).ifPresent(user -> {
            String resetToken = generateSecureToken();
            tokenService.storeResetToken(resetToken, user.getUserId(), resetTokenExpirationMs);

            // Delegate to EmailService — POC logs to console, production sends real email
            long expirationMinutes = resetTokenExpirationMs / 60000;
            emailService.sendPasswordResetEmail(email, resetToken, expirationMinutes);
        });

        // Same log message whether user exists or not — prevents log-based enumeration
        log.info("Forgot password requested for email: {}", email);
    }

    /**
     * BRD 5.6: Reset password flow.
     * Phase 1: Validate reset token in Redis (fast, no DB)
     * Phase 2: Update password + unlock account (DB transaction)
     * Phase 3: Cleanup — delete reset token + revoke session (Redis, outside transaction)
     */
    public void resetPassword(ResetPasswordRequest request) {
        // Phase 1: Redis lookup — is this token valid and not expired?
        UUID userId = tokenService.validateResetToken(request.getResetToken());
        if (userId == null) {
            throw new BadRequestException("Invalid or expired reset token");
        }

        // Phase 2: DB write — password change + account unlock are atomic
        updatePasswordAndUnlock(userId, request.getNewPassword());

        // Phase 3: Redis cleanup — outside transaction (best-effort)
        tokenService.deleteResetToken(request.getResetToken()); // One-time use — prevent replay
        tokenService.revokeAllTokens(userId); // Force re-login — account may be compromised

        log.info("Password reset and account unlocked for user: {}", userId);
    }

    /**
     * Atomic DB operation: update password + unlock + reset failed attempts.
     * If user not found for a valid token, it's a data integrity issue (500, not 400).
     */
    @Transactional
    protected void updatePasswordAndUnlock(UUID userId, String newPassword) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.error("Reset token references non-existent user: {}", userId);
                    return new RuntimeException("Data integrity error: user not found for valid reset token");
                });

        user.setPasswordHash(passwordEncoder.encode(newPassword)); // BCrypt strength 12
        user.setAccountLocked(false);
        user.setFailedLoginAttempts(0);
        user.setLockedAt(null);
        userRepository.save(user);
    }

    /** URL-safe base64, 256 bits. No dashes (unlike UUID), no URL encoding needed. */
    private String generateSecureToken() {
        byte[] bytes = new byte[RESET_TOKEN_BYTES];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
