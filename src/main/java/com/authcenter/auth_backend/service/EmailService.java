package com.authcenter.auth_backend.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    public void sendOtpEmail(String to, String otp) {
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setFrom("noreply@madhusudan.space");
        msg.setTo(to);
        msg.setSubject("Your OTP Code");
        msg.setText("Your OTP is: " + otp);
        mailSender.send(msg);
    }

    public void sendApprovalRequest(String to, String encryptedUserId, String approvalString, String email, String role, String link) {
        String subject = "Admin Approval Request";
        String body = "<html><body>" +
                "<h3>New Admin Account Request</h3>" +
                "<p><strong>User ID:</strong> " + encryptedUserId + "</p>" +
                "<p><strong>Email:</strong> " + email + "</p>" +
                "<p><strong>Role:</strong> " + role + "</p>" +
                "<p><strong>Approval Code:</strong> " + approvalString + "</p>" +
                "<a href='" + link + "'>Take Action</a>" +
                "</body></html>";

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(body, true);
            mailSender.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }
}