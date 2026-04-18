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
            // Single parse: verify signature + expiration + extract claims (~1-2ms)
            Claims claims = jwtProvider.parseTokenSafe(token);

            if (claims == null) {
                log.debug("JWT signature/expiration validation failed");
                filterChain.doFilter(request, response);
                return;
            }

            UUID userId = jwtProvider.getUserIdFromClaims(claims);

            // Redis revocation check (~1-5ms)
            if (!tokenService.isTokenValid(userId, token)) {
                log.debug("Token not found in Redis (revoked or expired) for user: {}", userId);
                filterChain.doFilter(request, response);
                return;
            }

            // Extract roles from already-parsed claims (no re-parse)
            List<String> roles = jwtProvider.getRolesFromClaims(claims);
            var authorities = roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .toList();

            var authentication = new UsernamePasswordAuthenticationToken(userId, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

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
