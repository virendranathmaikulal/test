package com.ecommerce.auth.service;

/**
 * Abstraction for sending emails.
 * POC: ConsoleEmailService (logs to console).
 * Production: swap with SesEmailService, SendGridEmailService, etc.
 */
public interface EmailService {

    void sendPasswordResetEmail(String toEmail, String resetToken, long expirationMinutes);
}
