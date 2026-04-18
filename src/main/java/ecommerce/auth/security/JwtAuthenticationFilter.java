package com.ecommerce.auth.security;

import com.ecommerce.auth.constants.AuthConstants;
import com.ecommerce.auth.service.TokenService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

/**
 * JWT authentication filter — runs on EVERY request (BRD 5.4).
 * Implements the fail-fast validation pattern:
 *   1. Extract token from header (free)
 *   2. Verify JWT signature + expiration (~1-2ms, CPU-bound)
 *   3. Check Redis for revocation (~1-5ms, network I/O)
 *   4. Set SecurityContext with userId + roles
 *
 * Total: ~2-7ms — well under the 50ms BRD target (Section 6.2).
 *
 * OncePerRequestFilter guarantees single execution even on internal forwards,
 * preventing double Redis lookups.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private final TokenService tokenService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        String token = extractToken(request);

        if (token != null) {
            // Step 1: Single parse — signature + expiration + claim extraction in one HMAC operation
            // Why single parse? Old approach called validate+getUserId+getRoles = 3 HMAC verifications
            Claims claims = jwtProvider.parseTokenSafe(token);

            if (claims == null) {
                // Invalid signature or expired — cheap check, no I/O. Fail fast.
                log.debug("JWT signature/expiration validation failed");
                filterChain.doFilter(request, response);
                return;
            }

            UUID userId = jwtProvider.getUserIdFromClaims(claims);

            // Step 2: Redis revocation check — is this token still active?
            // This is why we can revoke JWTs (logout, password reset, role change)
            // despite JWT being "stateless" by design. Redis adds just enough state.
            if (!tokenService.isTokenValid(userId, token)) {
                log.debug("Token not found in Redis (revoked or expired) for user: {}", userId);
                filterChain.doFilter(request, response);
                return;
            }

            // Step 3: Set SecurityContext — controllers access userId via @AuthenticationPrincipal
            List<String> roles = jwtProvider.getRolesFromClaims(claims);
            var authorities = roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role)) // Spring expects ROLE_ prefix
                    .toList();

            var authentication = new UsernamePasswordAuthenticationToken(userId, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        // If no token: SecurityContext stays empty → Spring Security handles 401 via authenticationEntryPoint

        filterChain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader(AuthConstants.AUTH_HEADER);
        if (header != null && header.startsWith(AuthConstants.BEARER_PREFIX)) {
            return header.substring(AuthConstants.BEARER_PREFIX.length());
        }
        return null;
    }
}
