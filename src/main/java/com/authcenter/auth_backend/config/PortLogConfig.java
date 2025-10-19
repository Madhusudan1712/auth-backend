package com.authcenter.auth_backend.config;

import org.springframework.boot.web.context.WebServerInitializedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class PortLogConfig {
    @Bean
    public ApplicationListener<WebServerInitializedEvent> serverPortLogger() {
        return event -> System.out.println("Active HTTP port: " + event.getWebServer().getPort());
    }
}