package com.sageit.csts.repositories;

import com.sageit.csts.entities.BlacklistedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface BlacklistedTokenRepository extends JpaRepository<BlacklistedToken, Long> {
    Optional<BlacklistedToken> findByToken(String token);
}

