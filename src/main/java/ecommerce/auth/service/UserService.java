package com.ecommerce.auth.service;

import com.ecommerce.auth.dto.request.RegisterRequest;
import com.ecommerce.auth.dto.response.UserResponse;
import com.ecommerce.auth.entity.Role;
import com.ecommerce.auth.entity.User;
import com.ecommerce.auth.enums.RoleName;
import com.ecommerce.auth.exception.BadRequestException;
import com.ecommerce.auth.repository.RoleRepository;
import com.ecommerce.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
        // Check email uniqueness at app level (DB constraint is the real guard)
        if (userRepository.existsByEmail(request.getEmail().toLowerCase())) {
            throw new BadRequestException("Email already registered");
        }

        User user = new User();
        user.setName(request.getName().trim());
        user.setEmail(request.getEmail().toLowerCase().trim());
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        user.setRoles(resolveRoles(request.getRole()));

        User saved = userRepository.save(user);
        log.info("User registered: {}", saved.getEmail());

        return UserResponse.from(saved);
    }

    private Set<Role> resolveRoles(String requestedRole) {
        Set<Role> roles = new HashSet<>();

        // Every user gets CUSTOMER (principle of least privilege)
        Role customerRole = roleRepository.findByRoleName(RoleName.CUSTOMER)
                .orElseThrow(() -> new RuntimeException("CUSTOMER role not found"));
        roles.add(customerRole);

        // If registering as seller, add SELLER too (per BRD 5.7.3)
        if ("SELLER".equalsIgnoreCase(requestedRole)) {
            Role sellerRole = roleRepository.findByRoleName(RoleName.SELLER)
                    .orElseThrow(() -> new RuntimeException("SELLER role not found"));
            roles.add(sellerRole);
        }

        // ADMIN role cannot be self-assigned via registration
        return roles;
    }
}
