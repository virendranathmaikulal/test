package com.ecommerce.auth.dto.response;

import com.ecommerce.auth.entity.User;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Getter
@Builder
public class UserResponse {

    private UUID userId;
    private String name;
    private String email;
    private Set<String> roles;
    private Instant createdAt;

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
}
