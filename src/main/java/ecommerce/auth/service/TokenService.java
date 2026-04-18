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

/**
 * Redis-based token store — handles access tokens, refresh tokens, and reset tokens.
 *
 * Why Redis-only (not DB)?
 * - Token validation is on the HOT PATH — every API call checks Redis (~1-3ms).
 * - DB lookup would add 5-20ms per request and saturate the connection pool.
 * - Tokens are ephemeral (15min-7days) — Redis TTL handles auto-cleanup. No cron jobs.
 * - BRD Section 7.2 explicitly defines Redis as the token store.
 *
 * Redis key patterns:
 *   user_token:{userId}          → access JWT     (TTL: 15 min)
 *   refresh_token:{opaqueToken}  → userId string   (TTL: 7 days)
 *   reset_token:{opaqueToken}    → userId string   (TTL: 15 min)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int REFRESH_TOKEN_BYTES = 32; // 256 bits — 2x entropy of UUID

    private final RedisTemplate<String, String> redisTemplate;

    // ─── Access Token Operations ─────────────────────────────────────────────

    /** Store access token. Key = user_token:{userId}. Single session per user — overwrites previous. */
    public void storeAccessToken(UUID userId, String token, long expirationMs) {
        String key = AuthConstants.USER_TOKEN_PREFIX + userId;
        redisTemplate.opsForValue().set(key, token, expirationMs, TimeUnit.MILLISECONDS);
        log.debug("Access token stored for user: {}", userId);
    }

    /** Validate access token — compares against Redis. Returns false if revoked or expired (TTL). */
    public boolean isTokenValid(UUID userId, String token) {
        String key = AuthConstants.USER_TOKEN_PREFIX + userId;
        String storedToken = redisTemplate.opsForValue().get(key);
        return token.equals(storedToken);
    }

    /** Revoke access token — used on logout, password reset, role change. */
    public void revokeAccessToken(UUID userId) {
        String key = AuthConstants.USER_TOKEN_PREFIX + userId;
        redisTemplate.delete(key);
        log.debug("Access token revoked for user: {}", userId);
    }

    // ─── Refresh Token Operations ────────────────────────────────────────────

    /**
     * Generate opaque refresh token (SecureRandom, 256 bits, URL-safe base64).
     * Opaque = no payload, can't be decoded. Just a key to look up userId in Redis.
     * Why not JWT? Refresh tokens don't need embedded claims. Simpler, shorter, can't be decoded.
     */
    public String generateAndStoreRefreshToken(UUID userId, long expirationMs) {
        String refreshToken = generateSecureToken();
        String key = AuthConstants.REFRESH_TOKEN_PREFIX + refreshToken;
        redisTemplate.opsForValue().set(key, userId.toString(), expirationMs, TimeUnit.MILLISECONDS);
        log.debug("Refresh token stored for user: {}", userId);
        return refreshToken;
    }

    /** Validate refresh token — returns userId if valid, null if expired/invalid. */
    public UUID validateRefreshToken(String refreshToken) {
        String key = AuthConstants.REFRESH_TOKEN_PREFIX + refreshToken;
        String userId = redisTemplate.opsForValue().get(key);
        return userId != null ? UUID.fromString(userId) : null;
    }

    /** Delete refresh token — called during rotation (old token invalidated after issuing new one). */
    public void deleteRefreshToken(String refreshToken) {
        String key = AuthConstants.REFRESH_TOKEN_PREFIX + refreshToken;
        redisTemplate.delete(key);
    }

    // ─── Password Reset Token Operations ─────────────────────────────────────

    /** Store reset token with TTL (15 min default). One-time use — deleted after password reset. */
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

    // ─── Bulk Revocation ─────────────────────────────────────────────────────

    /**
     * Revoke access token for a user. Refresh tokens are keyed by token value (not userId),
     * so they can only be revoked if the caller provides the specific token.
     * Otherwise, they expire naturally via Redis TTL.
     */
    public void revokeAllTokens(UUID userId) {
        revokeAccessToken(userId);
        log.debug("All access tokens revoked for user: {}", userId);
    }

    /** Generate URL-safe base64 token. 256 bits entropy — 2x stronger than UUID (122 bits). */
    private String generateSecureToken() {
        byte[] bytes = new byte[REFRESH_TOKEN_BYTES];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
