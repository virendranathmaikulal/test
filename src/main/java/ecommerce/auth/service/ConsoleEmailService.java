package com.ecommerce.auth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * POC implementation — prints reset token to console.
 * Replace with SES/SendGrid implementation for production.
 *
 * To swap: create a new class implementing EmailService,
 * annotate it with @Service and @Primary, and this one
 * will be overridden automatically.
 */
@Slf4j
@Service
public class ConsoleEmailService implements EmailService {

    @Override
    public void sendPasswordResetEmail(String toEmail, String resetToken, long expirationMinutes) {
        log.info("Sending password reset email to: {}", toEmail);

        // Console output for POC testing — remove in production
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════╗");
        System.out.println("║           PASSWORD RESET EMAIL (POC)            ║");
        System.out.println("╠══════════════════════════════════════════════════╣");
        System.out.println("║ To: " + toEmail);
        System.out.println("║ Reset Token: " + resetToken);
        System.out.println("║ Expires in: " + expirationMinutes + " minutes");
        System.out.println("║                                                  ");
        System.out.println("║ In production, this would be an email with a    ║");
        System.out.println("║ link like: https://app.com/reset?token=" + resetToken.substring(0, 8) + "...  ");
        System.out.println("╚══════════════════════════════════════════════════╝");
        System.out.println();
    }
}
