package com.hdu.is.secureapi.repo;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.hdu.is.secureapi.domain.User;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);
}
