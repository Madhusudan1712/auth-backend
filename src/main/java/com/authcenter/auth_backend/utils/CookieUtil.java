package com.authcenter.auth_backend.utils;

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
                                                                          long refreshExpiry,
                                                                          String cookieDomain) {
        boolean https = request.isSecure()
                || "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto"));
        String host = request.getServerName();
        String localAddr = request.getLocalAddr();
        boolean isIp = host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+");
        boolean isLoopback = "127.0.0.1".equals(localAddr) || "::1".equals(localAddr);
        boolean isLocal = host.equals("localhost") || host.equals("127.0.0.1") || isIp || host.endsWith(".local") || isLoopback;

                StringBuilder accessSetCookie = new StringBuilder();
                accessSetCookie.append("auth_token=").append(accessToken)
                                .append("; Max-Age=").append((int) Duration.ofMillis(accessExpiry).getSeconds())
                                .append("; Path=/; HttpOnly");
                StringBuilder refreshSetCookie = new StringBuilder();
                refreshSetCookie.append("refresh_token=").append(refreshToken)
                                .append("; Max-Age=").append((int) Duration.ofMillis(refreshExpiry).getSeconds())
                                .append("; Path=/; HttpOnly");

                if (isLocal) {
                        // Local dev: no Domain, no Secure, SameSite=Lax
                        accessSetCookie.append("; SameSite=Lax");
                        refreshSetCookie.append("; SameSite=Lax");
                } else {
                        // Always set Domain to .madhusudan.space for SSO across all subdomains
                        accessSetCookie.append("; Domain=.madhusudan.space");
                        refreshSetCookie.append("; Domain=.madhusudan.space");
                        accessSetCookie.append("; SameSite=None");
                        refreshSetCookie.append("; SameSite=None");
                        if (https) {
                                accessSetCookie.append("; Secure");
                                refreshSetCookie.append("; Secure");
                        }
                }

                response.addHeader("Set-Cookie", accessSetCookie.toString());
                response.addHeader("Set-Cookie", refreshSetCookie.toString());
        }
}
