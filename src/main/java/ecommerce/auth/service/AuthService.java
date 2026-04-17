package com.ecommerce.auth.service;

import com.ecommerce.auth.dto.request.LoginRequest;
import com.ecommerce.auth.dto.response.LoginResponse;
import com.ecommerce.auth.entity.User;
import com.ecommerce.auth.exception.AccountLockedException;
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
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 3;

    private final JwtProvider jwtProvider;
    private final TokenService tokenService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public LoginResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail().toLowerCase())
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        // Check if account is locked
        if (user.isAccountLocked()) {
            throw new AccountLockedException(
                    "Account is locked due to too many failed login attempts. Please reset your password to unlock.");
        }

        // Validate password manually (not via AuthenticationManager) so we can track failures
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            handleFailedLogin(user);
            throw new BadCredentialsException("Invalid email or password");
        }

        // Successful login — reset failed attempts
        if (user.getFailedLoginAttempts() > 0) {
            user.setFailedLoginAttempts(0);
            userRepository.save(user);
        }

        List<String> roles = user.getRoles().stream()
                .map(role -> role.getRoleName().name())
                .collect(Collectors.toList());

        String token = jwtProvider.generateToken(user.getUserId(), user.getEmail(), roles);
        tokenService.storeToken(user.getUserId(), token, jwtProvider.getExpirationMs());

        log.info("User logged in: {}", user.getEmail());

        return LoginResponse.builder()
                .accessToken(token)
                .expiresIn(jwtProvider.getExpirationMs() / 1000)
                .build();
    }

    private void handleFailedLogin(User user) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);

        if (attempts >= MAX_FAILED_ATTEMPTS) {
            user.setAccountLocked(true);
            user.setLockedAt(Instant.now());
            log.warn("Account locked for user: {} after {} failed attempts", user.getEmail(), attempts);
        }

        userRepository.save(user);
    }

    public void logout(UUID userId) {
        tokenService.revokeToken(userId);
        log.info("User logged out: {}", userId);
    }
}
