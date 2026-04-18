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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Admin operations — user management and role assignment (BRD 5.7.3, 5.7.6).
 *
 * Design decisions:
 * - readOnly=true on reads — Hibernate skips dirty checking (performance on paginated lists).
 * - DB writes and Redis revocation are separated — different failure domains.
 *   If Redis fails after role change, the DB change persists (correct behavior).
 * - Token revocation after role change — forces re-login so new JWT has updated roles.
 *   Without this, the old JWT still has stale roles until it expires.
 * - Pagination on user list — prevents OOM with 10K+ users. Max page size capped at 100.
 * - Uses UserResponse.adminView() — includes status, lock state, failed attempts.
 *   Regular users see UserResponse.from() which excludes these fields.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AdminService {

    private static final int MAX_PAGE_SIZE = 100; // Prevents ?size=999999 from loading entire DB

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final TokenService tokenService;

    /** Paginated user list — sorted by newest first. readOnly skips Hibernate dirty checking. */
    @Transactional(readOnly = true)
    public Page<UserResponse> getAllUsers(int page, int size) {
        int safeSize = Math.min(size, MAX_PAGE_SIZE);
        PageRequest pageRequest = PageRequest.of(page, safeSize, Sort.by("createdAt").descending());
        return userRepository.findAll(pageRequest).map(UserResponse::adminView);
    }

    @Transactional(readOnly = true)
    public UserResponse getUserById(UUID userId) {
        User user = findUserOrThrow(userId);
        return UserResponse.adminView(user);
    }

    /**
     * Add role — DB write in separate @Transactional, Redis revocation outside.
     * Why revoke token? JWT embeds roles at generation time. Role change doesn't
     * take effect until user gets a new JWT (re-login or refresh).
     */
    public UserResponse addRoleToUser(UUID userId, String roleName) {
        UserResponse response = addRoleTransactional(userId, roleName);
        tokenService.revokeAllTokens(userId); // Force re-login for fresh roles
        return response;
    }

    @Transactional
    protected UserResponse addRoleTransactional(UUID userId, String roleName) {
        User user = findUserOrThrow(userId);
        RoleName roleEnum = parseRoleName(roleName);
        Role role = findRoleOrThrow(roleEnum);

        if (user.getRoles().contains(role)) {
            throw new BadRequestException("User already has role: " + roleName);
        }

        user.getRoles().add(role);
        User saved = userRepository.save(user);
        log.info("Role {} added to user {}", roleName, userId);
        return UserResponse.adminView(saved);
    }

    /** Remove role — prevents removing the last role (user with 0 roles = broken state). */
    public UserResponse removeRoleFromUser(UUID userId, String roleName) {
        UserResponse response = removeRoleTransactional(userId, roleName);
        tokenService.revokeAllTokens(userId);
        return response;
    }

    @Transactional
    protected UserResponse removeRoleTransactional(UUID userId, String roleName) {
        User user = findUserOrThrow(userId);
        RoleName roleEnum = parseRoleName(roleName);
        Role role = findRoleOrThrow(roleEnum);

        if (!user.getRoles().contains(role)) {
            throw new BadRequestException("User does not have role: " + roleName);
        }
        if (user.getRoles().size() == 1) {
            throw new BadRequestException("Cannot remove the only role from a user");
        }

        user.getRoles().remove(role);
        User saved = userRepository.save(user);
        log.info("Role {} removed from user {}", roleName, userId);
        return UserResponse.adminView(saved);
    }

    /** Idempotent unlock — skips DB write if already unlocked. No unnecessary writes. */
    @Transactional
    public void unlockUser(UUID userId) {
        User user = findUserOrThrow(userId);
        if (!user.isAccountLocked()) {
            log.info("Account already unlocked for user: {}", userId);
            return;
        }
        user.setAccountLocked(false);
        user.setFailedLoginAttempts(0);
        user.setLockedAt(null);
        userRepository.save(user);
        log.info("Account unlocked by admin for user: {}", userId);
    }

    // --- Shared helpers — DRY principle, consistent error messages ---

    private User findUserOrThrow(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));
    }

    private Role findRoleOrThrow(RoleName roleName) {
        return roleRepository.findByRoleName(roleName)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found: " + roleName));
    }

    /** Parse string to enum — fails fast with 400 instead of letting invalid values reach the DB. */
    private RoleName parseRoleName(String roleName) {
        try {
            return RoleName.valueOf(roleName.toUpperCase().trim());
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Invalid role: " + roleName + ". Valid roles: CUSTOMER, SELLER, ADMIN");
        }
    }
}
