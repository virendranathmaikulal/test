package com.ecommerce.auth.service;

import com.ecommerce.auth.constants.AuthConstants;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

    private final RedisTemplate<String, String> redisTemplate;

    // --- Session token operations ---

    public void storeToken(UUID userId, String token, long expirationMs) {
        String key = AuthConstants.USER_TOKEN_PREFIX + userId;
        redisTemplate.opsForValue().set(key, token, expirationMs, TimeUnit.MILLISECONDS);
        log.debug("Token stored for user: {}", userId);
    }

    public boolean isTokenValid(UUID userId, String token) {
        String key = AuthConstants.USER_TOKEN_PREFIX + userId;
        String storedToken = redisTemplate.opsForValue().get(key);
        return token.equals(storedToken);
    }

    public void revokeToken(UUID userId) {
        String key = AuthConstants.USER_TOKEN_PREFIX + userId;
        redisTemplate.delete(key);
        log.debug("Token revoked for user: {}", userId);
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
}
