package com.hdu.is.secureapi.security;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

import com.hdu.is.secureapi.config.SecurityProperties;

/**
 * Throttles password guessing: after N failed attempts the account is locked for a while.
 * In-memory storage is fine for a single-instance teaching deployment.
 */
@Component
public class LoginAttemptService {

    private record Attempt(int count, Instant lockedUntil) {
    }

    private final Map<String, Attempt> attempts = new ConcurrentHashMap<>();
    private final int maxAttempts;
    private final long lockoutSeconds;

    public LoginAttemptService(SecurityProperties properties) {
        this.maxAttempts = properties.maxLoginAttempts();
        this.lockoutSeconds = properties.lockoutDuration().toSeconds();
    }

    public boolean isLocked(String username) {
        Attempt attempt = attempts.get(username);
        if (attempt == null || attempt.lockedUntil() == null) {
            return false;
        }
        if (Instant.now().isAfter(attempt.lockedUntil())) {
            attempts.remove(username);
            return false;
        }
        return true;
    }

    public void recordFailure(String username) {
        attempts.compute(username, (key, current) -> {
            int count = current == null ? 1 : current.count() + 1;
            Instant lockedUntil = count >= maxAttempts ? Instant.now().plusSeconds(lockoutSeconds) : null;
            return new Attempt(count, lockedUntil);
        });
    }

    public void recordSuccess(String username) {
        attempts.remove(username);
    }
}
