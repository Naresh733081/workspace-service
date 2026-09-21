package com.example.workspace.security;

import com.example.workspace.user.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    private final UserDetailsServiceImpl userDetailsService;
    private final RestAuthenticationEntryPoint authenticationEntryPoint;
    private final RestAccessDeniedHandler accessDeniedHandler;

    public SecurityConfig(UserDetailsServiceImpl userDetailsService,
                          RestAuthenticationEntryPoint authenticationEntryPoint,
                          RestAccessDeniedHandler accessDeniedHandler) {
        this.userDetailsService = userDetailsService;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.accessDeniedHandler = accessDeniedHandler;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/register", "/api/auth/login").permitAll()
                        // more specific rule must come BEFORE the general
                        // "anyRequest().authenticated()" rule below — Spring
                        // Security evaluates these in order and uses the first
                        // match, so if this were listed after anyRequest(), it
                        // would never be reached
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex
                        // Triggers (401 Unauthorized) when an unauthenticated user tries to access a protected route
                        .authenticationEntryPoint(authenticationEntryPoint)
                        // Triggers (403 Forbidden) when an authenticated user lacks the required roles/permissions
                        .accessDeniedHandler(accessDeniedHandler)
                );

        return http.build();
    }

    // bcrypt = salted + intentionally slow, so brute-forcing leaked hashes
    // is expensive. Used both when we hash a password at registration and
    // when DaoAuthenticationProvider checks a password at login.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // DaoAuthenticationProvider is the AuthenticationProvider implementation
    // that knows how to check a username/password pair against a
    // UserDetailsService + PasswordEncoder. This is the piece that actually
    // does "look the user up, check their password."
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    // AuthenticationManager is the entry point our controller calls. Under
    // the hood it delegates to the AuthenticationProvider(s) registered
    // above — we don't call DaoAuthenticationProvider directly, we go
    // through this manager.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}