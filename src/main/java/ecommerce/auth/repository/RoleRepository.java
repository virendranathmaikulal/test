package com.ecommerce.auth.repository;

import com.ecommerce.auth.entity.Role;
import com.ecommerce.auth.enums.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RoleRepository extends JpaRepository<Role, UUID> {

    Optional<Role> findByRoleName(RoleName roleName);
}
