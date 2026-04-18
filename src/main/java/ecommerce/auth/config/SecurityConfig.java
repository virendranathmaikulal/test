package com.ecommerce.auth.config;

import com.ecommerce.auth.security.JwtAuthenticationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Map;

/**
 * Central security configuration — defines authentication rules, password encoding,
 * and the JWT filter chain. All security decisions flow from here.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity // Enables @PreAuthorize on controllers (defense-in-depth with URL rules below)
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final ObjectMapper objectMapper; // Jackson — for JSON error responses

    /**
     * BCrypt with strength 12 (~250ms per hash).
     * Strength is a security parameter, not performance — slower = harder to brute force.
     * Strength 10 (default) was standard in 2015. 12 is the 2024+ recommendation.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // CSRF disabled — we use Bearer tokens, not cookies. CSRF only applies to cookie-based auth.
                .csrf(csrf -> csrf.disable())

                // Stateless — no server-side sessions. Every request authenticated via JWT.
                // This enables horizontal scaling: any instance can handle any request.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Custom JSON error responses — without these, Spring returns HTML login pages
                .exceptionHandling(ex -> ex
                        // 401 — no token or invalid token (replaces Spring's default HTML redirect)
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(HttpStatus.UNAUTHORIZED.value());
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            objectMapper.writeValue(response.getOutputStream(), Map.of(
                                    "code", HttpStatus.UNAUTHORIZED.value(),
                                    "status", "error",
                                    "message", "Authentication required",
                                    "timestamp", java.time.Instant.now().toString()
                            ));
                        })
                        // 403 — valid token but wrong role (e.g., CUSTOMER accessing /admin)
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setStatus(HttpStatus.FORBIDDEN.value());
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            objectMapper.writeValue(response.getOutputStream(), Map.of(
                                    "code", HttpStatus.FORBIDDEN.value(),
                                    "status", "error",
                                    "message", "Access denied: insufficient permissions",
                                    "timestamp", java.time.Instant.now().toString()
                            ));
                        })
                )

                // URL-level access rules — evaluated top-to-bottom, first match wins
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints — no token needed
                        .requestMatchers(
                                "/api/v1/user/register",     // Registration (user doesn't have token yet)
                                "/api/v1/login",             // Login (getting a token)
                                "/api/v1/user/forgot_password", // Locked out, no token
                                "/api/v1/user/reset_password",  // Resetting, no token
                                "/api/v1/auth/validate",     // Downstream services check any token (even invalid)
                                "/api/v1/auth/refresh",      // Access token expired, using refresh token
                                "/actuator/health"           // Health check for load balancer
                        ).permitAll()
                        // Admin-only — URL-level guard (+ @PreAuthorize on controller = defense-in-depth)
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        // Everything else requires a valid JWT
                        .anyRequest().authenticated()
                )

                // JWT filter runs BEFORE Spring's default UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
