package com.ecommerce.auth.service;

import com.ecommerce.auth.constants.AuthConstants;
import com.ecommerce.auth.dto.request.LoginRequest;
import com.ecommerce.auth.dto.response.LoginResponse;
import com.ecommerce.auth.entity.User;
import com.ecommerce.auth.exception.AccountLockedException;
import com.ecommerce.auth.exception.BadRequestException;
import com.ecommerce.auth.repository.UserRepository;
import com.ecommerce.auth.security.JwtProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtProvider jwtProvider;
    private final TokenService tokenService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Login flow per BRD 5.2:
     * 1. Validate credentials against DB
     * 2. Check account status (active, locked)
     * 3. Generate JWT with user_id, email, roles
     * 4. Store token in Redis (single session per user)
     * 5. Return token to client
     */
    public LoginResponse login(LoginRequest request) {
        // Step 1: Find user — same error message for "not found" and "wrong password" (prevents enumeration)
        User user = userRepository.findByEmail(request.getEmail().toLowerCase().trim())
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        // Step 2a: Check account status
        if (!AuthConstants.STATUS_ACTIVE.equals(user.getStatus())) {
            throw new BadRequestException("Account is not active. Current status: " + user.getStatus());
        }

        // Step 2b: Check account lock
        if (user.isAccountLocked()) {
            throw new AccountLockedException(
                    "Account is locked due to too many failed login attempts. Please reset your password to unlock.");
        }

        // Step 3: Validate password (BCrypt.matches — intentionally slow, ~100ms at strength 12)
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            handleFailedLogin(user);
            throw new BadCredentialsException("Invalid email or password");
        }

        // Step 4: Successful login — reset failed attempts (only if needed)
        resetFailedAttemptsIfNeeded(user);

        // Step 5: Generate JWT
        List<String> roles = user.getRoles().stream()
                .map(role -> role.getRoleName().name())
                .toList();

        String token = jwtProvider.generateToken(user.getUserId(), user.getEmail(), roles);

        // Step 6: Store in Redis (outside @Transactional — Redis failure shouldn't roll back DB)
        tokenService.storeToken(user.getUserId(), token, jwtProvider.getExpirationMs());

        log.info("User logged in: {}", user.getEmail());

        return LoginResponse.builder()
                .accessToken(token)
                .expiresIn(jwtProvider.getExpirationMs() / 1000)
                .build();
    }

    @Transactional
    protected void handleFailedLogin(User user) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);

        if (attempts >= AuthConstants.MAX_FAILED_LOGIN_ATTEMPTS) {
            user.setAccountLocked(true);
            user.setLockedAt(Instant.now());
            log.warn("Account locked for user: {} after {} failed attempts", user.getEmail(), attempts);
        } else {
            log.info("Failed login attempt {} of {} for user: {}",
                    attempts, AuthConstants.MAX_FAILED_LOGIN_ATTEMPTS, user.getEmail());
        }

        userRepository.save(user);
    }

    @Transactional
    protected void resetFailedAttemptsIfNeeded(User user) {
        if (user.getFailedLoginAttempts() > 0) {
            user.setFailedLoginAttempts(0);
            userRepository.save(user);
        }
    }

    public void logout(UUID userId) {
        tokenService.revokeToken(userId);
        log.info("User logged out: {}", userId);
    }
}
