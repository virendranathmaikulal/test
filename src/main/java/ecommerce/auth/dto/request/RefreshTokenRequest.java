package com.ecommerce.auth.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RefreshTokenRequest {

    @JsonProperty("refresh_token")
    @NotBlank(message = "Refresh token is required")
    @Size(max = 64, message = "Refresh token must not exceed 64 characters")
    private String refreshToken;
}
