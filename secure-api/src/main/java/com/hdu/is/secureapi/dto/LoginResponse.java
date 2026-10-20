package com.hdu.is.secureapi.dto;

public record LoginResponse(String token, String tokenType, long expiresIn) {
}
