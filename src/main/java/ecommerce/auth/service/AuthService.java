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

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int RESET_TOKEN_BYTES = 32; // 256 bits of entropy

    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.password-reset.expiration-ms}")
    private long resetTokenExpirationMs;

    /**
     * Forgot password per BRD 5.5:
     * 1. User provides registered email
     * 2. System generates password reset token
     * 3. Token stored in Redis with expiration
     * 4. Token sent to user via email (POC: logged at DEBUG)
     *
     * Always returns success to prevent email enumeration attacks.
     */
    public void forgotPassword(ForgotPasswordRequest request) {
        String email = request.getEmail().toLowerCase().trim();

        userRepository.findByEmail(email).ifPresent(user -> {
            // Generate cryptographically secure token (URL-safe base64, 256 bits)
            String resetToken = generateSecureToken();
            tokenService.storeResetToken(resetToken, user.getUserId(), resetTokenExpirationMs);

            // POC: log at DEBUG (never INFO in production — tokens in logs = security risk)
            // Production: send via email service (SES/SendGrid)
            log.debug("Password reset token generated for user: {}", user.getUserId());
            log.debug("Reset token: {}", resetToken);

            // This is the POC console output — remove in production
            System.out.println("=== PASSWORD RESET TOKEN for " + email + " ===");
            System.out.println(resetToken);
            System.out.println("=== TOKEN EXPIRES IN " + (resetTokenExpirationMs / 60000) + " MINUTES ===");
        });

        // Always log the same message regardless of whether user exists
        log.info("Forgot password requested for email: {}", email);
    }

    /**
     * Reset password per BRD 5.6:
     * 1. Validate reset token
     * 2. Verify token in Redis
     * 3. Update password
     * 4. Invalidate reset token
     *
     * Additional: unlock account + invalidate session (per updated requirements).
     */
    public void resetPassword(ResetPasswordRequest request) {
        // Step 1-2: Validate reset token in Redis
        UUID userId = tokenService.validateResetToken(request.getResetToken());
        if (userId == null) {
            throw new BadRequestException("Invalid or expired reset token");
        }

        // Step 3: Update password + unlock account (DB transaction)
        updatePasswordAndUnlock(userId, request.getNewPassword());

        // Step 4: Cleanup Redis (outside transaction — Redis failure shouldn't roll back password change)
        tokenService.deleteResetToken(request.getResetToken());
        tokenService.revokeToken(userId);

        log.info("Password reset and account unlocked for user: {}", userId);
    }

    @Transactional
    protected void updatePasswordAndUnlock(UUID userId, String newPassword) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.error("Reset token references non-existent user: {}", userId);
                    return new RuntimeException("Data integrity error: user not found for valid reset token");
                });

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setAccountLocked(false);
        user.setFailedLoginAttempts(0);
        user.setLockedAt(null);

        userRepository.save(user);
    }

    /**
     * Generates a URL-safe base64 token with 256 bits of entropy.
     * More secure than UUID (122 bits) and no dashes that need URL encoding.
     */
    private String generateSecureToken() {
        byte[] bytes = new byte[RESET_TOKEN_BYTES];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
