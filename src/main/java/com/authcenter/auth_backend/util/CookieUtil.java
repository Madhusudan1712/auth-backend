package com.authcenter.auth_backend.util;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.time.Duration;

public final class CookieUtil {

    private CookieUtil() {} // prevent instantiation

    public static void addAuthCookies(HttpServletRequest request,
                                      HttpServletResponse response,
                                      String accessToken,
                                      String refreshToken,
                                      long accessExpiry,
                                      long refreshExpiry) {
        boolean https = request.isSecure()
                || "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto"));
        String sameSite = https ? "None" : "Lax";
        String domain = "madhusudan.space"; // all subdomains share cookies

        String accessSetCookie = String.format(
                "auth_token=%s; Max-Age=%d; Path=/; Domain=%s; HttpOnly; SameSite=%s%s",
                accessToken,
                (int) Duration.ofMillis(accessExpiry).getSeconds(),
                domain,
                sameSite,
                https ? "; Secure" : ""
        );
        response.addHeader("Set-Cookie", accessSetCookie);

        String refreshSetCookie = String.format(
                "refresh_token=%s; Max-Age=%d; Path=/; Domain=%s; HttpOnly; SameSite=%s%s",
                refreshToken,
                (int) Duration.ofMillis(refreshExpiry).getSeconds(),
                domain,
                sameSite,
                https ? "; Secure" : ""
        );
        response.addHeader("Set-Cookie", refreshSetCookie);
    }
}
