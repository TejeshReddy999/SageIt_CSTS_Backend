package com.sageit.csts.controllers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/sageit/users")
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    @GetMapping("/me")
    public ResponseEntity<?> me(Authentication authentication) {
        if (authentication != null) {
            logger.info("User '{}' accessed /me endpoint with authorities {}",
                    authentication.getName(), authentication.getAuthorities());
            return ResponseEntity.ok(Map.of(
                    "username", authentication.getName(),
                    "authorities", authentication.getAuthorities()
            ));
        } else {
            logger.warn("Unauthorized access attempt to /me endpoint");
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
        }
    }
}
