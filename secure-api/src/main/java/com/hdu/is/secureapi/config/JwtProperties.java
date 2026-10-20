package com.hdu.is.secureapi.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * JWT settings. The secret must be Base64 encoded and decode to at least 256 bits.
 */
@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(String secret, String issuer, Duration expiration) {
}
