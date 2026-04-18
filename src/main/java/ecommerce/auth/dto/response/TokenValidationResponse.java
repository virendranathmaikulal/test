package com.ecommerce.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;

import java.util.List;
import java.util.UUID;

@Getter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenValidationResponse {

    private boolean valid;

    @JsonProperty("user_id")
    private UUID userId;

    private String email;
    private List<String> roles;
}
