package com.ecommerce.auth.service;

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
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AdminService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final TokenService tokenService;

    public List<UserResponse> getAllUsers() {
        return userRepository.findAll().stream()
                .map(UserResponse::from)
                .collect(Collectors.toList());
    }

    public UserResponse getUserById(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return UserResponse.from(user);
    }

    @Transactional
    public UserResponse addRoleToUser(UUID userId, String roleName) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        RoleName roleEnum = parseRoleName(roleName);

        Role role = roleRepository.findByRoleName(roleEnum)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found: " + roleName));

        if (user.getRoles().contains(role)) {
            throw new BadRequestException("User already has role: " + roleName);
        }

        user.getRoles().add(role);
        User saved = userRepository.save(user);

        // Invalidate session so new roles take effect on next login (JWT embeds roles)
        tokenService.revokeToken(userId);

        log.info("Role {} added to user {}", roleName, userId);
        return UserResponse.from(saved);
    }

    @Transactional
    public UserResponse removeRoleFromUser(UUID userId, String roleName) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        RoleName roleEnum = parseRoleName(roleName);

        Role role = roleRepository.findByRoleName(roleEnum)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found: " + roleName));

        if (!user.getRoles().contains(role)) {
            throw new BadRequestException("User does not have role: " + roleName);
        }

        // Prevent removing the last role
        if (user.getRoles().size() == 1) {
            throw new BadRequestException("Cannot remove the only role from a user");
        }

        user.getRoles().remove(role);
        User saved = userRepository.save(user);

        tokenService.revokeToken(userId);

        log.info("Role {} removed from user {}", roleName, userId);
        return UserResponse.from(saved);
    }

    @Transactional
    public void unlockUser(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        user.setAccountLocked(false);
        user.setFailedLoginAttempts(0);
        user.setLockedAt(null);
        userRepository.save(user);

        log.info("Account unlocked by admin for user: {}", userId);
    }

    private RoleName parseRoleName(String roleName) {
        try {
            return RoleName.valueOf(roleName.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Invalid role: " + roleName + ". Valid roles: CUSTOMER, SELLER, ADMIN");
        }
    }
}
