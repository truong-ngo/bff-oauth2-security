package com.example.authorizationserver.repository;

import com.example.authorizationserver.entity.UserDomain;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserDomain, Long> {
    Optional<UserDomain> findByUsername(String username);
    void deleteByUsername(String username);
    boolean existsByUsername(String username);
}
