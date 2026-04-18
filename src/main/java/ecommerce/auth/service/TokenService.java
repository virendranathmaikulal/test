package com.ecommerce.auth.service;

import com.ecommerce.auth.constants.AuthConstants;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int REFRESH_TOKEN_BYTES = 32;

    private final RedisTemplate<String, String> redisTemplate;

    // --- Access token operations ---

    public void storeAccessToken(UUID userId, String token, long expirationMs) {
        String key = AuthConstants.USER_TOKEN_PREFIX + userId;
        redisTemplate.opsForValue().set(key, token, expirationMs, TimeUnit.MILLISECONDS);
        log.debug("Access token stored for user: {}", userId);
    }

    public boolean isTokenValid(UUID userId, String token) {
        String key = AuthConstants.USER_TOKEN_PREFIX + userId;
        String storedToken = redisTemplate.opsForValue().get(key);
        return token.equals(storedToken);
    }

    public void revokeAccessToken(UUID userId) {
        String key = AuthConstants.USER_TOKEN_PREFIX + userId;
        redisTemplate.delete(key);
        log.debug("Access token revoked for user: {}", userId);
    }

    // --- Refresh token operations ---

    public String generateAndStoreRefreshToken(UUID userId, long expirationMs) {
        String refreshToken = generateSecureToken();
        String key = AuthConstants.REFRESH_TOKEN_PREFIX + refreshToken;
        redisTemplate.opsForValue().set(key, userId.toString(), expirationMs, TimeUnit.MILLISECONDS);
        log.debug("Refresh token stored for user: {}", userId);
        return refreshToken;
    }

    public UUID validateRefreshToken(String refreshToken) {
        String key = AuthConstants.REFRESH_TOKEN_PREFIX + refreshToken;
        String userId = redisTemplate.opsForValue().get(key);
        return userId != null ? UUID.fromString(userId) : null;
    }

    public void deleteRefreshToken(String refreshToken) {
        String key = AuthConstants.REFRESH_TOKEN_PREFIX + refreshToken;
        redisTemplate.delete(key);
    }

    // --- Password reset token operations ---

    public void storeResetToken(String resetToken, UUID userId, long expirationMs) {
        String key = AuthConstants.RESET_TOKEN_PREFIX + resetToken;
        redisTemplate.opsForValue().set(key, userId.toString(), expirationMs, TimeUnit.MILLISECONDS);
    }

    public UUID validateResetToken(String resetToken) {
        String key = AuthConstants.RESET_TOKEN_PREFIX + resetToken;
        String userId = redisTemplate.opsForValue().get(key);
        return userId != null ? UUID.fromString(userId) : null;
    }

    public void deleteResetToken(String resetToken) {
        String key = AuthConstants.RESET_TOKEN_PREFIX + resetToken;
        redisTemplate.delete(key);
    }

    // --- Revoke all tokens for a user (logout, password reset) ---

    public void revokeAllTokens(UUID userId) {
        revokeAccessToken(userId);
        // Note: refresh tokens are keyed by token value, not userId.
        // To revoke, the caller must provide the specific refresh token,
        // or the token expires naturally via TTL.
        log.debug("All access tokens revoked for user: {}", userId);
    }

    private String generateSecureToken() {
        byte[] bytes = new byte[REFRESH_TOKEN_BYTES];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
