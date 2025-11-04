package com.sageit.csts.security;

import com.sageit.csts.repositories.BlacklistedTokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {

    private final Key key;

    @Value("${jwt.access.expiration-ms}")
    private long accessExpirationMs;
    private final BlacklistedTokenRepository blacklistedTokenRepository;

    public JwtUtils(@Value("${jwt.secret}") String secret,BlacklistedTokenRepository blacklistedTokenRepository) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
        this.blacklistedTokenRepository = blacklistedTokenRepository;
    }

    public String generateAccessToken(String username) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + accessExpirationMs);
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(key)
                .compact();
    }

    public String getUsernameFromToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    public Long getExpiryFromToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder().setSigningKey(key).build()
                    .parseClaimsJws(token)
                    .getBody();
            return claims.getExpiration().getTime(); // expiry in milliseconds
        } catch (JwtException e) {
            return null; // invalid token
        }
    }
}
