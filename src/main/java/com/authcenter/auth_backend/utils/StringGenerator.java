package com.authcenter.auth_backend.utils;


import java.security.SecureRandom;
import java.util.UUID;

public class StringGenerator {

    private static final String ALPHA_NUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final SecureRandom RANDOM = new SecureRandom();

    public static String generateRandomString(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(ALPHA_NUMERIC.charAt(RANDOM.nextInt(ALPHA_NUMERIC.length())));
        }
        return sb.toString();
    }

    public static String generateUUIDString() {
        return UUID.randomUUID()
                .toString()
                .replace("-", "");
    }

    public static String generateShortUUID(int length) {
        String uuid = generateUUIDString();
        return uuid.substring(0, Math.min(length, uuid.length()));
    }
}
