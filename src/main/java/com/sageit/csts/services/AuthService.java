package com.sageit.csts.services;

import com.sageit.csts.entities.RefreshToken;
import com.sageit.csts.entities.User;
import com.sageit.csts.repositories.RefreshTokenRepository;
import com.sageit.csts.repositories.RoleRepository;
import com.sageit.csts.repositories.UserRepository;
import com.sageit.csts.security.JwtUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;

    @Value("${jwt.refresh.expiration-ms}")
    private long refreshExpirationMs;

    public AuthService(AuthenticationManager authenticationManager,
                       UserRepository userRepository,
                       RoleRepository roleRepository,
                       RefreshTokenRepository refreshTokenRepository,
                       BCryptPasswordEncoder passwordEncoder,
                       JwtUtils jwtUtils) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
    }

    public User register(String username, String email, String password) {
        if (userRepository.existsByUsername(username)) throw new RuntimeException("Username taken");
        if (userRepository.existsByEmail(email)) throw new RuntimeException("Email taken");

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        var userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("ROLE_USER not found"));
        user.setRoles(Set.of(userRole));
        return userRepository.save(user);
    }

    public String loginAndCreateAccessToken(String username, String password) {
        var auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        return jwtUtils.generateAccessToken(username);
    }

    public RefreshToken createRefreshToken(User user) {
        RefreshToken token = new RefreshToken();
        token.setUser(user);
        token.setExpiryDate(Instant.now().plusMillis(refreshExpirationMs));
        token.setToken(UUID.randomUUID().toString());
        token.setRevoked(false);
        return refreshTokenRepository.save(token);
    }

    public RefreshToken verifyRefreshToken(String token) {
        RefreshToken t = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));
        if (t.isRevoked() || t.getExpiryDate().isBefore(Instant.now())) {
            throw new RuntimeException("Refresh token expired or revoked");
        }
        return t;
    }

    public void revokeRefreshToken(RefreshToken t) {
        t.setRevoked(true);
        refreshTokenRepository.save(t);
    }

    public void revokeAllUserRefreshTokens(User user) {
        refreshTokenRepository.deleteByUser(user);
    }
}
