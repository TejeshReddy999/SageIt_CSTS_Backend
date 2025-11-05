package com.sageit.csts.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Entity
@Table(name = "blacklisted_tokens")
public class BlacklistedToken {

    // Getters and Setters
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Setter
    @Column(nullable = false, unique = true)
    private String token;

    @Setter
    @Column(nullable = false)
    private LocalDateTime expiry;

    // Constructors
    public BlacklistedToken() {}
    public BlacklistedToken(String token, LocalDateTime expiry) {
        this.token = token;
        this.expiry = expiry;
    }

}


