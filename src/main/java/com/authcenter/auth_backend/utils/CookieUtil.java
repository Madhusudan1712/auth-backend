package com.authcenter.auth_backend.utils;

import jakarta.servlet.http.Cookie;
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

                if (!isLocal) {
                    if (cookieDomain != null && !cookieDomain.isEmpty()) {
                        // Always prefix with dot in prod
                        accessSetCookie.append("; Domain=.").append(cookieDomain);
                        refreshSetCookie.append("; Domain=.").append(cookieDomain);
                    }
                    accessSetCookie.append("; SameSite=None");
                    refreshSetCookie.append("; SameSite=None");
                    if (https) {
                        accessSetCookie.append("; Secure");
                        refreshSetCookie.append("; Secure");
                    }
                } else {
                    // Local dev: do NOT set Domain (host-only cookie)
                    accessSetCookie.append("; SameSite=Lax");
                    refreshSetCookie.append("; SameSite=Lax");
                }


                response.addHeader("Set-Cookie", accessSetCookie.toString());
                response.addHeader("Set-Cookie", refreshSetCookie.toString());
        }

    public static void clearAuthCookies(HttpServletRequest request,
                                        HttpServletResponse response,
                                        String cookieDomain,
                                        boolean isLocal) {
        boolean https = request.isSecure()
                || "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto"));

        for (String name : new String[]{"auth_token", "refresh_token"}) {
            Cookie cookie = new Cookie(name, "");
            cookie.setMaxAge(0);
            cookie.setHttpOnly(true);
            cookie.setSecure(https);
            cookie.setPath("/");
            if (!isLocal && cookieDomain != null && !cookieDomain.isBlank()) {
                cookie.setDomain("." + cookieDomain); // must match prod cookies
            }
            response.addCookie(cookie);
        }
    }

}
