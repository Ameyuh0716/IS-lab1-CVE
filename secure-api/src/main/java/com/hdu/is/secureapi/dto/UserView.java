package com.hdu.is.secureapi.dto;

import java.time.Instant;

/** Response projection - never exposes the password hash. */
public record UserView(Long id, String username, String role, Instant createdAt) {
}
