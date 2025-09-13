package com.authcenter.auth_backend.service;

import com.authcenter.auth_backend.model.OtpPurpose;
import com.authcenter.auth_backend.model.Role;
import com.authcenter.auth_backend.model.Status;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Year;
import java.util.Objects;

@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    private final JavaMailSender mailSender;

    @Value("${authcenter.approval.link.base}")
    private String approvalBase;

    @Value("${mail.from.address:noreply@madhusudan.space}")
    private String fromAddress;

    @Value("${mail.from.name:AuthCenter}")
    private String fromName;

    @Value("${mail.replyto:admin@madhusudan.space}")
    private String replyTo;

    @Value("${mail.unsubscribe.url:}")
    private String unsubscribeUrl;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    private String buildListUnsubscribeHeader() {
        if (unsubscribeUrl != null && !unsubscribeUrl.isBlank() && unsubscribeUrl.startsWith("https://")) {
            return "<" + unsubscribeUrl + ">, <mailto:" + fromAddress + "?subject=unsubscribe>";
        } else {
            String host = extractHostname(approvalBase);
            return "<mailto:" + fromAddress + "?subject=unsubscribe>, <https://" + host + "/unsubscribe>";
        }
    }

    private static String extractHostname(String url) {
        if (url == null) return "madhusudan.space";
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            return host == null ? "madhusudan.space" : host;
        } catch (Exception ex) {
            return "madhusudan.space";
        }
    }

    /**
     * Sends an OTP email to the specified recipient.
     * @param to The recipient's email address
     * @param otp The OTP to send
     * @param otpPurpose The purpose of the OTP
     * @param application The application name
     * @throws MessagingException If there's an error sending the email
     * @throws UnsupportedEncodingException If there's an encoding error
     * @throws RuntimeException If any other error occurs
     */
    public void sendOtpEmail(String to, String otp, OtpPurpose otpPurpose, String application) 
            throws MessagingException, UnsupportedEncodingException {
        Objects.requireNonNull(to, "Recipient email required");
        log.debug("Preparing to send OTP email to: {}", to);
        
        String subject = "Your AuthCenter OTP";
        String plain = "Dear User," + System.lineSeparator() + System.lineSeparator() +
                "Your requested OTP for " + otpPurpose + " in " + application + " application." + System.lineSeparator() + System.lineSeparator() +
                "OTP is: " + otp + System.lineSeparator() + System.lineSeparator() +
                "Note: This OTP is valid for 10 minutes." + System.lineSeparator() + System.lineSeparator() +
                "This is an auto-generated email. Do not reply to this email." + System.lineSeparator() + System.lineSeparator() +
                "© " + Year.now().getValue() + " madhusudan.space — This message was sent on behalf of AuthCenter.";

        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, false, "UTF-8");

        helper.setFrom(fromAddress, fromName);
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(plain); // plain text only
        helper.setReplyTo(replyTo);

        // Simple delivery-helpful headers
        message.addHeader("List-Unsubscribe", buildListUnsubscribeHeader());
        message.addHeader("X-Mailer", "AuthCenter Mailer");

        try {
            mailSender.send(message);
            log.info("OTP email sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send OTP email to: " + to, e);
            throw e; // Re-throw to allow proper error handling upstream
        }
    }

    public void sendRegistrationSuccess(String to, String domain){
        Objects.requireNonNull(to, "Recipient email required");
        String subject = "Registration success";

        String plain = "Dear User," + System.lineSeparator() + System.lineSeparator() +
                "Your registration is success ..!" + System.lineSeparator() + System.lineSeparator() +
                "Please try to login with your email and password " + domain + System.lineSeparator() + System.lineSeparator() +
                "This is an auto-generated email. Do not reply to this email." + System.lineSeparator() + System.lineSeparator() +
                "© " + Year.now().getValue() + " madhusudan.space — This message was sent on behalf of AuthCenter.";

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, false, "UTF-8");

            helper.setFrom(fromAddress, fromName);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(plain); // plain text only
            helper.setReplyTo(replyTo);

            // Simple delivery-helpful headers
            message.addHeader("List-Unsubscribe", buildListUnsubscribeHeader());
            message.addHeader("X-Mailer", "AuthCenter Mailer");

            mailSender.send(message);
            log.info("Registration success email sent to {}", to);
        } catch (MessagingException | UnsupportedEncodingException ex) {
            log.error("Failed to send Registration success email to {}: {}", to, ex.getMessage(), ex);
        } catch (Exception ex) {
            log.error("Unexpected error sending Registration success to {}: {}", to, ex.getMessage(), ex);
        }
    }

    public void sendApprovalRequest(String to,
                                    String encryptedUserId,
                                    String approvalString,
                                    String userEmail,
                                    Role role) {

        Objects.requireNonNull(to, "Recipient email required");

        String subject = "Admin approval request — Review required";

        if (approvalBase == null || approvalBase.isBlank()) {
            log.error("approval.link.base is not configured. Please set authcenter.approval.link.base in application.properties");
            return;
        }
        if (!approvalBase.startsWith("https://")) {
            log.warn("approval.link.base is not HTTPS ({}). For best deliverability use https and avoid raw ports.", approvalBase);
        }

        try {
            // URL encode parameters safely
            String encodedId = URLEncoder.encode(encryptedUserId == null ? "" : encryptedUserId, StandardCharsets.UTF_8);
            String encodedApproval = URLEncoder.encode(approvalString == null ? "" : approvalString, StandardCharsets.UTF_8);
            String encodedRole = URLEncoder.encode(role == null ? "" : role.name(), StandardCharsets.UTF_8);

            // ✅ Include role in the approval link
            String actionLink = String.format(
                    "%s?userId=%s&approvalString=%s&role=%s",
                    approvalBase,
                    encodedId,
                    encodedApproval,
                    encodedRole
            );

            // Build plain text email body
            StringBuilder plain = new StringBuilder();
            plain.append("Hello Madhusudan,").append(System.lineSeparator()).append(System.lineSeparator());
            plain.append("A new administrator account request requires your review. Please approve or reject by verifying the account. Below are the details:")
                    .append(System.lineSeparator()).append(System.lineSeparator());
            plain.append("User ID:\t").append(encryptedUserId).append(System.lineSeparator());
            plain.append("Email:\t").append(userEmail).append(System.lineSeparator());
            plain.append("Role:\t").append(role).append(System.lineSeparator());
            plain.append("Approval code:\t").append(approvalString).append(System.lineSeparator()).append(System.lineSeparator());
            plain.append("Take action (approve or reject):").append(System.lineSeparator());
            plain.append(actionLink).append(System.lineSeparator()).append(System.lineSeparator());
            plain.append("If you don't have access or believe this is in error, contact ")
                    .append(replyTo).append(".").append(System.lineSeparator()).append(System.lineSeparator());
            plain.append("© ").append(Year.now().getValue()).append(" madhusudan.space — This message was sent on behalf of AuthCenter.");

            String plainTextBody = plain.toString();

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, false, "UTF-8");

            helper.setFrom(fromAddress, fromName);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(plainTextBody);
            helper.setReplyTo(replyTo);

            // Helpful headers
            message.addHeader("List-Unsubscribe", buildListUnsubscribeHeader());
            message.addHeader("X-Mailer", "AuthCenter Mailer");

            mailSender.send(message);
            log.info("Approval request email sent to {} for applicant {}", to, userEmail);

        } catch (UnsupportedEncodingException e) {
            log.error("Failed to encode URL parameters for approval link: {}", e.getMessage(), e);
        } catch (MessagingException e) {
            log.error("Failed to construct/send approval email to {}: {}", to, e.getMessage(), e);
        } catch (Exception e) {
            log.error("Unexpected error while sending approval email to {}: {}", to, e.getMessage(), e);
        }
    }

    public void sendApprovedOrRejectedEmail(String to, String domain, Status status, String reason) {
        Objects.requireNonNull(to, "Recipient email required");

        String subject = switch (status) {
            case APPROVED -> "Your account got approved";
            case REJECTED -> "Your account got rejected";
            case PENDING -> "Your account is pending approval";
            default -> "Your account status has changed";
        };

        String plain = "Dear User," + System.lineSeparator() + System.lineSeparator() +
                "Your account have been "+ status +" for application " + domain + System.lineSeparator() + System.lineSeparator() +
                "Comment :" + reason + System.lineSeparator() + System.lineSeparator() +
                "This is an auto-generated email. Do not reply to this email." + System.lineSeparator() + System.lineSeparator() +
                "© " + Year.now().getValue() + " madhusudan.space — This message was sent on behalf of AuthCenter.";

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, false, "UTF-8");

            helper.setFrom(fromAddress, fromName);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(plain); // plain text only
            helper.setReplyTo(replyTo);

            // Simple delivery-helpful headers
            message.addHeader("List-Unsubscribe", buildListUnsubscribeHeader());
            message.addHeader("X-Mailer", "AuthCenter Mailer");

            mailSender.send(message);
            log.info("Approval status email sent to {}", to);
        } catch (MessagingException | UnsupportedEncodingException ex) {
            log.error("Failed to send Approval status email to {}: {}", to, ex.getMessage(), ex);
        } catch (Exception ex) {
            log.error("Unexpected error sending Approval status to {}: {}", to, ex.getMessage(), ex);
        }
    }

    public void sendPasswordResetSuccess(String to, String domain){
        Objects.requireNonNull(to, "Recipient email required");
        String subject = "Password Reset success";

        String plain = "Dear User," + System.lineSeparator() + System.lineSeparator() +
                "Password reset is success ..!" + System.lineSeparator() + System.lineSeparator() +
                "Please try to login with your updated email and password " + domain + System.lineSeparator() + System.lineSeparator() +
                "This is an auto-generated email. Do not reply to this email." + System.lineSeparator() + System.lineSeparator() +
                "© " + Year.now().getValue() + " madhusudan.space — This message was sent on behalf of AuthCenter.";

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, false, "UTF-8");

            helper.setFrom(fromAddress, fromName);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(plain); // plain text only
            helper.setReplyTo(replyTo);

            // Simple delivery-helpful headers
            message.addHeader("List-Unsubscribe", buildListUnsubscribeHeader());
            message.addHeader("X-Mailer", "AuthCenter Mailer");

            mailSender.send(message);
            log.info("Password reset success email sent to {}", to);
        } catch (MessagingException | UnsupportedEncodingException ex) {
            log.error("Failed to send Password reset success email to {}: {}", to, ex.getMessage(), ex);
        } catch (Exception ex) {
            log.error("Unexpected error sending Password reset success to {}: {}", to, ex.getMessage(), ex);
        }
    }

}
