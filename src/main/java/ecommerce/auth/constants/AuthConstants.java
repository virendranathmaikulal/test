package com.ecommerce.auth.constants;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

/**
 * Centralized constants — eliminates magic strings across the codebase.
 * Any change (e.g., Redis key prefix) is a single-point edit.
 * Private constructor prevents instantiation (utility class pattern).
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class AuthConstants {

    // HTTP header names — used in JwtAuthenticationFilter and controllers
    public static final String AUTH_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";

    // Redis key prefixes — defines the namespace for each token type
    // Pattern: prefix + identifier → value. TTL handles auto-cleanup.
    public static final String USER_TOKEN_PREFIX = "user_token:";       // user_token:{userId} → JWT
    public static final String REFRESH_TOKEN_PREFIX = "refresh_token:"; // refresh_token:{token} → userId
    public static final String RESET_TOKEN_PREFIX = "reset_token:";     // reset_token:{token} → userId

    // OAuth2 standard token type
    public static final String TOKEN_TYPE_BEARER = "Bearer";

    // API response envelope status values
    public static final String RESPONSE_SUCCESS = "success";
    public static final String RESPONSE_ERROR = "error";

    // User account status — stored in DB, checked during login
    public static final String STATUS_ACTIVE = "ACTIVE";
    public static final String STATUS_INACTIVE = "INACTIVE";
    public static final String STATUS_SUSPENDED = "SUSPENDED";

    // Account lock threshold — after this many failed attempts, account is locked
    public static final int MAX_FAILED_LOGIN_ATTEMPTS = 3;

    // JWT claim keys — used when building and reading JWT payload
    public static final String CLAIM_EMAIL = "email";
    public static final String CLAIM_ROLES = "roles";
}
