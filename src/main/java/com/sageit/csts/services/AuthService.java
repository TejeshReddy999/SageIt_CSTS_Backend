package com.sageit.csts.services;

import com.sageit.csts.entities.RefreshToken;
import com.sageit.csts.entities.User;
import com.sageit.csts.repositories.RefreshTokenRepository;
import com.sageit.csts.repositories.RoleRepository;
import com.sageit.csts.repositories.UserRepository;
import com.sageit.csts.security.JwtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

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
        logger.info("AuthService initialized");
    }

    public User register(String username, String email, String password) {
        logger.info("Attempting to register user: {}", username);
        if (userRepository.existsByUsername(username)) {
            logger.warn("Username '{}' is already taken", username);
            throw new RuntimeException("Username taken");
        }
        if (userRepository.existsByEmail(email)) {
            logger.warn("Email '{}' is already taken", email);
            throw new RuntimeException("Email taken");
        }

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        var userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("ROLE_USER not found"));
        user.setRoles(Set.of(userRole));

        User savedUser = userRepository.save(user);
        logger.info("User '{}' registered successfully with ID {}", username, savedUser.getId());
        return savedUser;
    }

    public String loginAndCreateAccessToken(String username, String password) {
        logger.info("Attempting login for user: {}", username);
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        String token = jwtUtils.generateAccessToken(username);
        logger.info("Access token generated for user: {}", username);
        return token;
    }

    public RefreshToken createRefreshToken(User user) {
        RefreshToken token = new RefreshToken();
        token.setUser(user);
        token.setExpiryDate(Instant.now().plusMillis(refreshExpirationMs));
        token.setToken(UUID.randomUUID().toString());
        token.setRevoked(false);
        RefreshToken savedToken = refreshTokenRepository.save(token);
        logger.info("Refresh token created for user: {}", user.getUsername());
        return savedToken;
    }

    public RefreshToken verifyRefreshToken(String token) {
        logger.debug("Verifying refresh token: {}", token);
        RefreshToken t = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> {
                    logger.warn("Refresh token not found: {}", token);
                    return new RuntimeException("Refresh token not found");
                });

        if (t.isRevoked() || t.getExpiryDate().isBefore(Instant.now())) {
            logger.warn("Refresh token expired or revoked for user: {}", t.getUser().getUsername());
            throw new RuntimeException("Refresh token expired or revoked");
        }
        logger.debug("Refresh token verified for user: {}", t.getUser().getUsername());
        return t;
    }

    public void revokeRefreshToken(RefreshToken t) {
        t.setRevoked(true);
        refreshTokenRepository.save(t);
        logger.info("Refresh token revoked for user: {}", t.getUser().getUsername());
    }

    public void revokeAllUserRefreshTokens(User user) {
        refreshTokenRepository.deleteByUser(user);
        logger.info("All refresh tokens revoked for user: {}", user.getUsername());
    }
}
