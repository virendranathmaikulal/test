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

/**
 * JWT token generation and validation using HMAC-SHA256.
 * Chosen over RSA for POC simplicity — symmetric key, single service.
 * Production upgrade path: RSA/EC for asymmetric verification by downstream services.
 */
@Slf4j
@Component
public class JwtProvider {

    private static final int MIN_SECRET_KEY_BYTES = 32; // 256 bits minimum for HS256

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expiration-ms}")
    private long jwtExpirationMs;

    private SecretKey signingKey;

    /**
     * Fail-fast: validate key length at startup, not at first token generation.
     * A short key would cause a cryptic WeakKeyException later — this gives a clear message.
     */
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

    /**
     * Generate access token with user identity + roles embedded (BRD 5.7.5).
     * Embedding roles avoids a DB/service call on every request by downstream services.
     * Trade-off: role changes don't take effect until user re-logs in.
     */
    public String generateToken(UUID userId, String email, List<String> roles) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtExpirationMs);

        return Jwts.builder()
                .subject(userId.toString())              // sub claim — who this token belongs to
                .claim(AuthConstants.CLAIM_EMAIL, email)  // custom claim — avoids DB lookup for email
                .claim(AuthConstants.CLAIM_ROLES, roles)  // custom claim — enables stateless authorization
                .issuedAt(now)                            // iat — when token was created
                .expiration(expiry)                       // exp — when token becomes invalid
                .signWith(signingKey)                     // HMAC-SHA256 signature
                .compact();
    }

    /** Parse and verify — throws on invalid tokens. Use parseTokenSafe() for filter chain. */
    public Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Safe parse — returns null instead of throwing. Used in the filter chain where
     * invalid tokens should result in "no authentication" (not an exception).
     * Single parse for the entire request (~1-2ms vs ~3-6ms for multiple calls).
     */
    public Claims parseTokenSafe(String token) {
        try {
            return parseToken(token);
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Invalid JWT: {}", e.getMessage());
            return null;
        }
    }

    // --- Claims-based accessors (use after single parse — no re-verification) ---

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

    // --- Token-based accessors (convenience — each call re-parses the token) ---

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
