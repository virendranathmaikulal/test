package com.ecommerce.auth.service;

/**
 * Email abstraction — Dependency Inversion Principle (SOLID).
 * PasswordService depends on this interface, not a concrete implementation.
 *
 * POC: ConsoleEmailService (logs to console).
 * Production: Create SesEmailService or SendGridEmailService implementing this interface,
 *             annotate with @Service and @Primary — zero changes to PasswordService.
 */
public interface EmailService {

    void sendPasswordResetEmail(String toEmail, String resetToken, long expirationMinutes);
}
