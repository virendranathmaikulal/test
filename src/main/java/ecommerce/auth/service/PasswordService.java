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

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordService {

    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.password-reset.expiration-ms}")
    private long resetTokenExpirationMs;

    /**
     * Always returns success to prevent email enumeration attacks (BRD design).
     * If email exists, generates a reset token and stores it in Redis.
     * In production, this would send an email. For POC, we log the token.
     */
    public void forgotPassword(ForgotPasswordRequest request) {
        String email = request.getEmail().toLowerCase().trim();

        userRepository.findByEmail(email).ifPresent(user -> {
            String resetToken = UUID.randomUUID().toString();
            tokenService.storeResetToken(resetToken, user.getUserId(), resetTokenExpirationMs);

            // POC: log the token. Production: send via email service (SES/SendGrid)
            log.info("Password reset token for {}: {}", email, resetToken);
        });

        // Always log the same message regardless of whether user exists
        log.info("Forgot password requested for email: {}", email);
    }

    /**
     * Validates reset token, updates password, unlocks account, and invalidates session.
     */
    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        UUID userId = tokenService.validateResetToken(request.getResetToken());

        if (userId == null) {
            throw new BadRequestException("Invalid or expired reset token");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BadRequestException("User not found"));

        // Update password
        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));

        // Unlock account (core requirement: reset password unlocks the account)
        user.setAccountLocked(false);
        user.setFailedLoginAttempts(0);
        user.setLockedAt(null);

        userRepository.save(user);

        // Invalidate reset token (one-time use)
        tokenService.deleteResetToken(request.getResetToken());

        // Invalidate current session — force re-login (security: account may be compromised)
        tokenService.revokeToken(userId);

        log.info("Password reset and account unlocked for user: {}", userId);
    }
}
