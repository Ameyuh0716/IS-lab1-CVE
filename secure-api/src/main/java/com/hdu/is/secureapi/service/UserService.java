package com.hdu.is.secureapi.service;

import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.hdu.is.secureapi.domain.User;
import com.hdu.is.secureapi.dto.UserView;
import com.hdu.is.secureapi.repo.UserRepository;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Transactional(readOnly = true)
    public List<UserView> findAll() {
        return userRepository.findAll().stream().map(this::toView).toList();
    }

    private UserView toView(User user) {
        return new UserView(user.getId(), user.getUsername(), user.getRole(), user.getCreatedAt());
    }
}
