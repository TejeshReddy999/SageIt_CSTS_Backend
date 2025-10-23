package com.sageit.csts.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;
    private final JwtUtils jwtUtils;

    public SecurityConfig(CustomUserDetailsService uds, JwtUtils jwtUtils) {
        this.userDetailsService = uds;
        this.jwtUtils = jwtUtils;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(jwtUtils, userDetailsService);

        http
                .csrf().disable()
                .authorizeHttpRequests()
                .requestMatchers("/api/sageit/auth/**", "/h2-console/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .sessionManagement().disable();

        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        http.headers().frameOptions().disable();

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
