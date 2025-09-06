package com.authcenter.auth_backend.utils;

import java.net.URI;
import java.net.URISyntaxException;

public class UrlUtils {

    public static String extractHost(String redirect) {
        if (redirect == null || redirect.isBlank()) {
            return "";
        }

        try {
            URI uri = new URI(redirect);
            return uri.getHost() != null ? uri.getHost() : redirect;
        } catch (URISyntaxException e) {
            return redirect;
        }
    }
}
