package com.ecommerce.auth.security;

import com.ecommerce.auth.constants.AuthConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Slf4j
@Component
public class JwtProvider {

    private static final int MIN_SECRET_KEY_BYTES = 32; // 256 bits for HS256

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expiration-ms}")
    private long jwtExpirationMs;

    private SecretKey signingKey;

    @PostConstruct
    public void init() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < MIN_SECRET_KEY_BYTES) {
            throw new IllegalStateException(
                    "JWT secret key must be at least " + MIN_SECRET_KEY_BYTES + " bytes (256 bits) for HS256. " +
                    "Current key is " + keyBytes.length + " bytes. Set a longer JWT_SECRET environment variable.");
        }
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
        log.info("JWT provider initialized with HS256, token TTL: {}ms", jwtExpirationMs);
    }

    public String generateToken(UUID userId, String email, List<String> roles) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtExpirationMs);

        return Jwts.builder()
                .subject(userId.toString())
                .claim(AuthConstants.CLAIM_EMAIL, email)
                .claim(AuthConstants.CLAIM_ROLES, roles)
                .issuedAt(now)
                .expiration(expiry)
                .signWith(signingKey)
                .compact();
    }

    /**
     * Parse and verify token. Returns null if invalid (signature, expiration, malformed).
     * Use this instead of calling validateToken() + getUserIdFromToken() + getRolesFromToken()
     * separately — avoids parsing the token multiple times.
     */
    public Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Safe parse — returns null instead of throwing on invalid tokens.
     * Single parse for the entire filter chain (performance: ~1-2ms instead of ~3-6ms).
     */
    public Claims parseTokenSafe(String token) {
        try {
            return parseToken(token);
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Invalid JWT: {}", e.getMessage());
            return null;
        }
    }

    public UUID getUserIdFromClaims(Claims claims) {
        return UUID.fromString(claims.getSubject());
    }

    @SuppressWarnings("unchecked")
    public List<String> getRolesFromClaims(Claims claims) {
        return claims.get(AuthConstants.CLAIM_ROLES, List.class);
    }

    public String getEmailFromClaims(Claims claims) {
        return claims.get(AuthConstants.CLAIM_EMAIL, String.class);
    }

    // --- Convenience methods for one-off use (e.g., logout, validate endpoint) ---

    public boolean validateToken(String token) {
        return parseTokenSafe(token) != null;
    }

    public UUID getUserIdFromToken(String token) {
        return UUID.fromString(parseToken(token).getSubject());
    }

    @SuppressWarnings("unchecked")
    public List<String> getRolesFromToken(String token) {
        return parseToken(token).get(AuthConstants.CLAIM_ROLES, List.class);
    }

    public String getEmailFromToken(String token) {
        return parseToken(token).get(AuthConstants.CLAIM_EMAIL, String.class);
    }

    public long getExpirationMs() {
        return jwtExpirationMs;
    }
}
