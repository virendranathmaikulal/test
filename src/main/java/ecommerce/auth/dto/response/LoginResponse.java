package com.ecommerce.auth.dto.response;

import com.ecommerce.auth.constants.AuthConstants;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class LoginResponse {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("token_type")
    @Builder.Default
    private String tokenType = AuthConstants.TOKEN_TYPE_BEARER;

    @JsonProperty("expires_in")
    private long expiresIn; // seconds
}
