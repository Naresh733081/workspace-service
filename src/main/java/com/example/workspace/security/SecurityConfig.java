package com.example.workspace.security;

import com.example.workspace.user.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private final UserDetailsServiceImpl userDetailsService;
    private final RestAuthenticationEntryPoint authenticationEntryPoint;
    private final RestAccessDeniedHandler accessDeniedHandler;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(UserDetailsServiceImpl userDetailsService,
                          RestAuthenticationEntryPoint authenticationEntryPoint,
                          RestAccessDeniedHandler accessDeniedHandler,
                          JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.userDetailsService = userDetailsService;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.accessDeniedHandler = accessDeniedHandler;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
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
                )
                // this is the actual switch. STATELESS means: never create a
                // session, never consult one even if a stray JSESSIONID cookie
                // shows up on a request. Every request is authenticated purely
                // from what it carries with it (the bearer token) — nothing
                // the server remembers about prior requests.
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // Our filter needs to run BEFORE Spring's own
                // UsernamePasswordAuthenticationFilter (the one that handles
                // form-login style POSTs) in the chain's execution order, so
                // that by the time authorization checks run, SecurityContext
                // is already populated if a valid token was present.
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

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