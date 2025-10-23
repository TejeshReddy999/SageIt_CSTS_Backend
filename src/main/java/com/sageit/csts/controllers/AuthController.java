package com.sageit.csts.controllers;

import com.sageit.csts.entities.RefreshToken;
import com.sageit.csts.entities.User;
import com.sageit.csts.repositories.UserRepository;
import com.sageit.csts.security.JwtUtils;
import com.sageit.csts.services.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/api/sageit/auth")
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;

    @Value("${app.refresh.cookie-name}")
    private String refreshCookieName;

    @Value("${app.refresh.cookie-secure}")
    private boolean cookieSecure;

    @Value("${app.refresh.http-only}")
    private boolean cookieHttpOnly;

    public AuthController(AuthService authService, UserRepository userRepository, JwtUtils jwtUtils) {
        this.authService = authService;
        this.userRepository = userRepository;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String,String> body) {
        var user = authService.register(body.get("username"), body.get("email"), body.get("password"));
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("id", user.getId(), "username", user.getUsername()));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String,String> body, HttpServletResponse response) {
        String username = body.get("username");
        String password = body.get("password");
        String accessToken = authService.loginAndCreateAccessToken(username, password);
        User user = userRepository.findByUsername(username).orElseThrow();
        RefreshToken refreshToken = authService.createRefreshToken(user);
        Cookie cookie = new Cookie(refreshCookieName, refreshToken.getToken());
        cookie.setHttpOnly(cookieHttpOnly);
        cookie.setSecure(cookieSecure);
        cookie.setPath("/");
        cookie.setMaxAge((int) (refreshToken.getExpiryDate().getEpochSecond() - Instant.now().getEpochSecond()));
        response.addCookie(cookie);

        return ResponseEntity.ok(Map.of("accessToken", accessToken, "tokenType", "Bearer"));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No refresh token");
        String token = null;
        for (Cookie c : cookies) {
            if (c.getName().equals(refreshCookieName)) token = c.getValue();
        }
        if (token == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No refresh token");

        RefreshToken rt = authService.verifyRefreshToken(token);
        String username = rt.getUser().getUsername();
        String newAccessToken = jwtUtils.generateAccessToken(username);

        authService.revokeRefreshToken(rt);
        RefreshToken newRt = authService.createRefreshToken(rt.getUser());
        Cookie cookie = new Cookie(refreshCookieName, newRt.getToken());
        cookie.setHttpOnly(cookieHttpOnly);
        cookie.setSecure(cookieSecure);
        cookie.setPath("/");
        cookie.setMaxAge((int) (newRt.getExpiryDate().getEpochSecond() - Instant.now().getEpochSecond()));
        response.addCookie(cookie);

        return ResponseEntity.ok(Map.of("accessToken", newAccessToken, "tokenType", "Bearer"));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie c : cookies) {
                if (c.getName().equals(refreshCookieName)) {
                    String token = c.getValue();
                    try {
                        RefreshToken rt = authService.verifyRefreshToken(token);
                        authService.revokeRefreshToken(rt);
                    } catch (Exception ignored) {}
                    Cookie clear = new Cookie(refreshCookieName, "");
                    clear.setMaxAge(0);
                    clear.setPath("/");
                    response.addCookie(clear);
                }
            }
        }
        return ResponseEntity.ok(Map.of("message", "logged out"));
    }
}
