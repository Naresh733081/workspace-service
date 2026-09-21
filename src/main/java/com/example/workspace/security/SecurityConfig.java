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
                )
                //session gets created the first time login writes a
                // SecurityContext to it, and NOT before. We're just naming
                // that default now instead of leaving it unstated. The
                // alternatives are ALWAYS (create one for every request,
                // wasteful), NEVER (Security won't create one, but will read
                // an existing one), and STATELESS (Security won't create OR
                // read a session at all — this is what JWT will switch us to)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        // on successful login, issue a brand-new session ID
                        // rather than reusing whatever session (if any) existed
                        // before authentication. This is the framework default —
                        // again, naming it rather than leaving it implicit.
                        // Defends against session fixation: without this, an
                        // attacker who gets a victim to browse using a session
                        // ID the attacker already knows could hijack that
                        // session the moment the victim logs in on it.
                        .sessionFixation(fixation -> fixation.changeSessionId())
                )
                // logout is a Spring Security filter, not a controller method —
                // it's declared as part of the filter chain, same layer as
                // authentication, not something AuthController implements
                .logout(logout -> logout
                        .logoutUrl("/api/auth/logout")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        // default logout success behavior is an HTTP redirect
                        // (built for browser form-based logout) — we're an API,
                        // so we want a plain 200 instead
                        .logoutSuccessHandler((request, response, authentication) ->
                                response.setStatus(org.springframework.http.HttpStatus.OK.value()))
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