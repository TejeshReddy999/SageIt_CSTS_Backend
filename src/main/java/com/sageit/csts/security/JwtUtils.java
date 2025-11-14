package com.sageit.csts.security;

import com.sageit.csts.repositories.BlacklistedTokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    private final Key key;

    @Value("${jwt.access.expiration-ms}")
    private long accessExpirationMs;

    private final BlacklistedTokenRepository blacklistedTokenRepository;

    public JwtUtils(@Value("${jwt.secret}") String secret, BlacklistedTokenRepository blacklistedTokenRepository) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
        this.blacklistedTokenRepository = blacklistedTokenRepository;
    }

    public String generateAccessToken(String username) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + accessExpirationMs);
        String token = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(key)
                .compact();
        logger.info("Generated new access token for user: {} with expiry: {}", username, expiry);
        return token;
    }

    public String getUsernameFromToken(String token) {
        try {
            String username = Jwts.parserBuilder().setSigningKey(key).build()
                    .parseClaimsJws(token).getBody().getSubject();
            logger.debug("Extracted username '{}' from token", username);
            return username;
        } catch (JwtException e) {
            logger.error("Failed to extract username from token", e);
            return null;
        }
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            logger.debug("Token validation successful");
            return true;
        } catch (JwtException e) {
            logger.warn("Invalid JWT token", e);
            return false;
        }
    }

    public Long getExpiryFromToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder().setSigningKey(key).build()
                    .parseClaimsJws(token)
                    .getBody();
            long expiryMillis = claims.getExpiration().getTime();
            logger.debug("Token expiry retrieved: {}", new Date(expiryMillis));
            return expiryMillis;
        } catch (JwtException e) {
            logger.error("Failed to get expiry from token", e);
            return null;
        }
    }
}
