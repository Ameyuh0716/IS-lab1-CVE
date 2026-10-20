package com.hdu.is.secureapi.dto;

import java.time.Instant;

public record PostView(Long id, String title, String body, String author, Instant createdAt) {
}
