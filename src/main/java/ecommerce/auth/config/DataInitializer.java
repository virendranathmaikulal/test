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

/**
 * Startup data seeder — BRD Section 5.7.2.
 *
 * Design decisions:
 * - CommandLineRunner (not @PostConstruct) — runs after full Spring context is ready,
 *   ensuring PasswordEncoder and Repositories are initialized.
 * - Separate @Transactional for roles and admin — if admin creation fails (bad password config),
 *   roles still persist. Next startup only retries admin creation.
 * - Idempotent — safe to run on every startup. Checks existence before creating.
 * - Admin gets ALL roles — BRD says "full system privileges." Without CUSTOMER/SELLER roles,
 *   admin can't access endpoints guarded by those specific roles.
 * - Admin password validated at startup — fail-fast if misconfigured. Don't let a weak
 *   admin password into production.
 * - Admin credentials from environment variables — never hardcoded in source.
 */
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
        initRoles();      // Must run first — admin creation depends on roles existing
        initAdminUser();
    }

    /** Seed roles from enum. Separate transaction — persists even if admin creation fails. */
    @Transactional
    protected void initRoles() {
        Arrays.stream(RoleName.values()).forEach(roleName -> {
            if (roleRepository.findByRoleName(roleName).isEmpty()) {
                roleRepository.save(new Role(roleName));
                log.info("Created role: {}", roleName);
            }
        });
    }

    /** Create admin with all roles. Validates password length. Normalizes email. */
    @Transactional
    protected void initAdminUser() {
        if (userRepository.findByEmail(adminEmail).isPresent()) {
            log.info("Admin user already exists, skipping creation");
            return;
        }

        // Fail-fast — don't let a 3-character admin password into the system
        if (adminPassword == null || adminPassword.length() < 8) {
            throw new IllegalStateException(
                    "Admin password must be at least 8 characters. Set ADMIN_PASSWORD environment variable.");
        }

        // Admin gets every role — can access all endpoints regardless of role checks
        Set<Role> adminRoles = new HashSet<>();
        for (RoleName roleName : RoleName.values()) {
            Role role = roleRepository.findByRoleName(roleName)
                    .orElseThrow(() -> new IllegalStateException(
                            "Role " + roleName + " not found. Ensure initRoles() ran successfully."));
            adminRoles.add(role);
        }

        User admin = new User();
        admin.setName(adminName);
        admin.setEmail(adminEmail.toLowerCase().trim()); // Same normalization as registration
        admin.setPasswordHash(passwordEncoder.encode(adminPassword));
        admin.setRoles(adminRoles);

        userRepository.save(admin);
        log.info("Default admin user created with email: {} and {} roles", adminEmail, adminRoles.size());
    }
}
