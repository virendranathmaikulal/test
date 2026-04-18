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

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public UserResponse register(RegisterRequest request) {
        String normalizedEmail = request.getEmail().toLowerCase().trim();

        // App-level check (fast path for obvious duplicates)
        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new BadRequestException("Email already registered");
        }

        User user = new User();
        user.setName(request.getName().trim());
        user.setEmail(normalizedEmail);
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        user.setRoles(resolveRoles(request.getRole()));

        try {
            User saved = userRepository.save(user);
            log.info("User registered: {}", saved.getEmail());
            return UserResponse.from(saved);
        } catch (DataIntegrityViolationException ex) {
            // Race condition: two concurrent requests passed the existsByEmail check
            // DB unique constraint caught it — return a clean 409
            log.warn("Duplicate email registration attempt caught by DB constraint: {}", normalizedEmail);
            throw new BadRequestException("Email already registered");
        }
    }

    private Set<Role> resolveRoles(String requestedRole) {
        Set<Role> roles = new HashSet<>();

        Role customerRole = roleRepository.findByRoleName(RoleName.CUSTOMER)
                .orElseThrow(() -> new ResourceNotFoundException("System role CUSTOMER not configured"));
        roles.add(customerRole);

        if (RoleName.SELLER.name().equalsIgnoreCase(requestedRole)) {
            Role sellerRole = roleRepository.findByRoleName(RoleName.SELLER)
                    .orElseThrow(() -> new ResourceNotFoundException("System role SELLER not configured"));
            roles.add(sellerRole);
        }

        return roles;
    }
}
