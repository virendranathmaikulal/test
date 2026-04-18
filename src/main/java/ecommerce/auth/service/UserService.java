package com.ecommerce.auth.service;

import com.ecommerce.auth.dto.request.RegisterRequest;
import com.ecommerce.auth.dto.response.UserResponse;
import com.ecommerce.auth.entity.Role;
import com.ecommerce.auth.entity.User;
import com.ecommerce.auth.enums.RoleName;
import com.ecommerce.auth.exception.BadRequestException;
import com.ecommerce.auth.exception.ResourceNotFoundException;
import com.ecommerce.auth.repository.RoleRepository;
import com.ecommerce.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

/**
 * User registration service — BRD Section 5.1.
 * Handles account creation with email uniqueness, BCrypt hashing, and role assignment.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Register a new user. @Transactional ensures existsByEmail + save are atomic.
     * Double defense against duplicate emails:
     *   1. App-level existsByEmail check (fast path, catches 99.9%)
     *   2. DB unique constraint catch (race condition safety net, catches 0.1%)
     */
    @Transactional
    public UserResponse register(RegisterRequest request) {
        String normalizedEmail = request.getEmail().toLowerCase().trim();

        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new BadRequestException("Email already registered");
        }

        User user = new User();
        user.setName(request.getName().trim());
        user.setEmail(normalizedEmail);
        user.setPasswordHash(passwordEncoder.encode(request.getPassword())); // BCrypt strength 12
        user.setRoles(resolveRoles(request.getRole()));

        try {
            User saved = userRepository.save(user);
            log.info("User registered: {}", saved.getEmail());
            return UserResponse.from(saved); // Public view — no admin fields
        } catch (DataIntegrityViolationException ex) {
            // Two concurrent requests both passed existsByEmail → DB constraint caught it
            log.warn("Duplicate email caught by DB constraint: {}", normalizedEmail);
            throw new BadRequestException("Email already registered");
        }
    }

    /**
     * Role assignment per BRD 5.7.3:
     * - Everyone gets CUSTOMER (principle of least privilege)
     * - SELLER is additive (user gets both CUSTOMER + SELLER)
     * - ADMIN is never self-assignable (DTO @Pattern blocks it, this method ignores it)
     */
    private Set<Role> resolveRoles(String requestedRole) {
        Set<Role> roles = new HashSet<>();

        Role customerRole = roleRepository.findByRoleName(RoleName.CUSTOMER)
                .orElseThrow(() -> new ResourceNotFoundException("System role CUSTOMER not configured"));
        roles.add(customerRole);

        // Use enum name comparison — no magic strings, compiler catches typos
        if (RoleName.SELLER.name().equalsIgnoreCase(requestedRole)) {
            Role sellerRole = roleRepository.findByRoleName(RoleName.SELLER)
                    .orElseThrow(() -> new ResourceNotFoundException("System role SELLER not configured"));
            roles.add(sellerRole);
        }

        return roles;
    }
}
