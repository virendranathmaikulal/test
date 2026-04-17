package com.ecommerce.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RoleUpdateRequest {

    @NotBlank(message = "Role name is required")
    private String roleName;
}
