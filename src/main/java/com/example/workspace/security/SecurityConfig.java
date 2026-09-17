package com.example.workspace.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    // Just added spring-security for the PasswordEncoder bean below. Problem is,
    // once it's on the classpath Spring auto-locks every endpoint behind a login
    // form by default — don't want that yet, so permitAll() everywhere for now.
    //
    // This is temporary. Real auth (JWT filter, protected routes) comes in a
    // later commits, and this whole method gets rewritten then. Don't take this
    // config as a reference for anything real production web.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // no cookies/sessions/forms yet, so CSRF isn't doing anything for us here
                // TODO: swap for .requestMatchers("/api/auth/**").permitAll().anyRequest().authenticated()
                // once JWT is in
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());

        return http.build();
    }

    // bcrypt = salted + slow on purpose, so brute-forcing hashes is expensive.
    // used in AuthController when we register a user.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}