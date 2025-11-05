package com.sageit.csts.security;

import com.sageit.csts.repositories.BlacklistedTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    private final CustomUserDetailsService userDetailsService;
    private final JwtUtils jwtUtils;
    private final BlacklistedTokenRepository blacklistedTokenRepository;

    public SecurityConfig(CustomUserDetailsService uds, JwtUtils jwtUtils, BlacklistedTokenRepository blacklistedTokenRepository) {
        this.userDetailsService = uds;
        this.jwtUtils = jwtUtils;
        this.blacklistedTokenRepository = blacklistedTokenRepository;
        logger.info("SecurityConfig initialized with CustomUserDetailsService, JwtUtils, and BlacklistedTokenRepository");
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        logger.info("Creating JwtAuthenticationFilter bean");
        return new JwtAuthenticationFilter(jwtUtils, userDetailsService, blacklistedTokenRepository);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        logger.info("Configuring SecurityFilterChain");

        http
                .csrf().disable()
                .authorizeHttpRequests()
                .requestMatchers("/api/sageit/auth/**", "/h2-console/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .sessionManagement().disable();

        // Use the filter bean
        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        logger.info("JwtAuthenticationFilter added to security filter chain");

        http.headers().frameOptions().disable();
        logger.debug("Frame options disabled for H2 console");

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        logger.info("BCryptPasswordEncoder bean created");
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        logger.info("AuthenticationManager bean created");
        return config.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        logger.info("Configuring CORS");
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:3000")); // React app URL
        configuration.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        configuration.setAllowCredentials(true); // Important for cookies!

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        logger.debug("CORS configuration applied for all endpoints");
        return source;
    }
}
