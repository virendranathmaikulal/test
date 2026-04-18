package com.ecommerce.auth.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RoleUpdateRequest {

    @JsonProperty("role_name")
    @NotBlank(message = "Role name is required")
    @Pattern(regexp = "^(CUSTOMER|SELLER|ADMIN)$", message = "Role must be CUSTOMER, SELLER, or ADMIN")
    private String roleName;
}
