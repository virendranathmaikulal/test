package com.ecommerce.auth.dto.response;

import lombok.Builder;
import lombok.Getter;

import java.util.List;
import java.util.UUID;

@Getter
@Builder
public class TokenValidationResponse {

    private boolean valid;
    private UUID userId;
    private String email;
    private List<String> roles;
}
