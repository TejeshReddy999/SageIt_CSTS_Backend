package com.sageit.csts.services;


import com.sageit.csts.repositories.BlacklistedTokenRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class TokenCleanupService {

    private final BlacklistedTokenRepository blacklistedTokenRepository;

    @Scheduled(fixedRate = 3600000)
    public void removeExpiredTokens() {
        blacklistedTokenRepository.deleteAll(
                blacklistedTokenRepository.findAll().stream()
                        .filter(token -> token.getExpiry().isBefore(LocalDateTime.now()))
                        .toList()
        );
        System.out.println("Expired blacklisted tokens cleaned up at " + LocalDateTime.now());
    }
}
