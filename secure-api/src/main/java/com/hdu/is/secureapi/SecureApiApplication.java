package com.hdu.is.secureapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * The default in-memory user auto-configuration is excluded on purpose: authentication is handled
 * by the JWT filter chain, so no framework-generated account should exist.
 */
@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
@ConfigurationPropertiesScan
public class SecureApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecureApiApplication.class, args);
    }
}
