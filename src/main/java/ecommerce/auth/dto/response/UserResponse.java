package com.ecommerce.auth.dto.response;

import com.ecommerce.auth.entity.User;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Getter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserResponse {

    private UUID userId;
    private String name;
    private String email;
    private Set<String> roles;
    private Instant createdAt;

    // Admin-only fields — null (excluded from JSON) for non-admin responses
    private String status;
    private Boolean accountLocked;
    private Integer failedLoginAttempts;
    private Instant lockedAt;

    /**
     * Public projection — registration, self-profile. No sensitive admin fields.
     */
    public static UserResponse from(User user) {
        return UserResponse.builder()
                .userId(user.getUserId())
                .name(user.getName())
                .email(user.getEmail())
                .roles(user.getRoles().stream()
                        .map(role -> role.getRoleName().name())
                        .collect(Collectors.toSet()))
                .createdAt(user.getCreatedAt())
                .build();
    }

    /**
     * Admin projection — includes account status, lock state, failed attempts.
     */
    public static UserResponse adminView(User user) {
        return UserResponse.builder()
                .userId(user.getUserId())
                .name(user.getName())
                .email(user.getEmail())
                .roles(user.getRoles().stream()
                        .map(role -> role.getRoleName().name())
                        .collect(Collectors.toSet()))
                .status(user.getStatus())
                .accountLocked(user.isAccountLocked())
                .failedLoginAttempts(user.getFailedLoginAttempts())
                .lockedAt(user.getLockedAt())
                .createdAt(user.getCreatedAt())
                .build();
    }
}
