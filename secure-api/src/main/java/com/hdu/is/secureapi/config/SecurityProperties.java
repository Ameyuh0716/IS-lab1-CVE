package com.hdu.is.secureapi.config;

import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.security")
public record SecurityProperties(
        int maxLoginAttempts,
        Duration lockoutDuration,
        List<String> corsAllowedOrigins) {

    public SecurityProperties {
        corsAllowedOrigins = corsAllowedOrigins == null ? List.of() : List.copyOf(corsAllowedOrigins);
    }
}
