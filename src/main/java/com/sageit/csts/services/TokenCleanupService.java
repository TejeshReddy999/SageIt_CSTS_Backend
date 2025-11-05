package com.sageit.csts.services;

import com.sageit.csts.repositories.BlacklistedTokenRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class TokenCleanupService {

    private static final Logger logger = LoggerFactory.getLogger(TokenCleanupService.class);

    private final BlacklistedTokenRepository blacklistedTokenRepository;

    // Runs every hour
    @Scheduled(fixedRate = 3600000)
    public void removeExpiredTokens() {
        var expiredTokens = blacklistedTokenRepository.findAll().stream()
                .filter(token -> token.getExpiry().isBefore(LocalDateTime.now()))
                .toList();

        blacklistedTokenRepository.deleteAll(expiredTokens);

        if (!expiredTokens.isEmpty()) {
            logger.info("Expired blacklisted tokens cleaned up at {}. Count: {}", LocalDateTime.now(), expiredTokens.size());
        } else {
            logger.debug("No expired blacklisted tokens to clean at {}", LocalDateTime.now());
        }
    }
}
