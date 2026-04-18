package com.ecommerce.auth.config;

import com.ecommerce.auth.entity.Role;
import com.ecommerce.auth.entity.User;
import com.ecommerce.auth.enums.RoleName;
import com.ecommerce.auth.repository.RoleRepository;
import com.ecommerce.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.admin.email}")
    private String adminEmail;

    @Value("${app.admin.password}")
    private String adminPassword;

    @Value("${app.admin.name}")
    private String adminName;

    @Override
    public void run(String... args) {
        initRoles();
        initAdminUser();
    }

    /**
     * Seed all roles defined in RoleName enum.
     * Separate transaction — role creation persists even if admin creation fails.
     */
    @Transactional
    protected void initRoles() {
        Arrays.stream(RoleName.values()).forEach(roleName -> {
            if (roleRepository.findByRoleName(roleName).isEmpty()) {
                roleRepository.save(new Role(roleName));
                log.info("Created role: {}", roleName);
            }
        });
    }

    /**
     * Create default admin user per BRD 5.7.2:
     * - System checks whether an Admin user exists
     * - If no Admin exists, create one with configured credentials
     * - Admin gets all roles (full system privileges)
     */
    @Transactional
    protected void initAdminUser() {
        if (userRepository.findByEmail(adminEmail).isPresent()) {
            log.info("Admin user already exists, skipping creation");
            return;
        }

        // Validate admin password meets minimum security requirements
        if (adminPassword == null || adminPassword.length() < 8) {
            throw new IllegalStateException(
                    "Admin password must be at least 8 characters. Set ADMIN_PASSWORD environment variable.");
        }

        // Admin gets all roles — full system privileges per BRD 5.7.2
        Set<Role> adminRoles = new HashSet<>();
        for (RoleName roleName : RoleName.values()) {
            Role role = roleRepository.findByRoleName(roleName)
                    .orElseThrow(() -> new IllegalStateException(
                            "Role " + roleName + " not found. Ensure initRoles() ran successfully."));
            adminRoles.add(role);
        }

        User admin = new User();
        admin.setName(adminName);
        admin.setEmail(adminEmail.toLowerCase().trim());
        admin.setPasswordHash(passwordEncoder.encode(adminPassword));
        admin.setRoles(adminRoles);

        userRepository.save(admin);
        log.info("Default admin user created with email: {} and roles: {}", adminEmail, adminRoles.size());
    }
}
