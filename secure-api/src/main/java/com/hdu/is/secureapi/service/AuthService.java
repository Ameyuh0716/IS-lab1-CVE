package com.hdu.is.secureapi.service;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.hdu.is.secureapi.domain.User;
import com.hdu.is.secureapi.dto.LoginResponse;
import com.hdu.is.secureapi.exception.AccountLockedException;
import com.hdu.is.secureapi.repo.UserRepository;
import com.hdu.is.secureapi.security.JwtService;
import com.hdu.is.secureapi.security.LoginAttemptService;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final LoginAttemptService loginAttemptService;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                       JwtService jwtService, LoginAttemptService loginAttemptService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.loginAttemptService = loginAttemptService;
    }

    public LoginResponse login(String username, String password) {
        if (loginAttemptService.isLocked(username)) {
            throw new AccountLockedException("Too many failed attempts. Try again later.");
        }

        User user = userRepository.findByUsername(username).orElse(null);
        // Always run the hash comparison to keep the response time independent of user existence.
        String hash = user != null ? user.getPasswordHash() : passwordEncoder.encode("timing-equalizer");
        boolean matches = passwordEncoder.matches(password, hash);

        if (user == null || !matches) {
            loginAttemptService.recordFailure(username);
            throw new BadCredentialsException("Invalid username or password");
        }

        loginAttemptService.recordSuccess(username);
        String token = jwtService.issueToken(user.getUsername(), user.getRole());
        return new LoginResponse(token, "Bearer", jwtService.expirationSeconds());
    }
}
