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
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
public class SecurityConfig {

    private final UserDetailsServiceImpl userDetailsService;
    private final RestAuthenticationEntryPoint authenticationEntryPoint;
    private final RestAccessDeniedHandler accessDeniedHandler;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CorsConfigurationSource corsConfigurationSource;
    private final RateLimitFilter rateLimitFilter;


    public SecurityConfig(UserDetailsServiceImpl userDetailsService,
                          RestAuthenticationEntryPoint authenticationEntryPoint,
                          RestAccessDeniedHandler accessDeniedHandler,
                          JwtAuthenticationFilter jwtAuthenticationFilter,
                          CorsConfigurationSource corsConfigurationSource,
                          RateLimitFilter rateLimitFilter) {
        this.userDetailsService = userDetailsService;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.accessDeniedHandler = accessDeniedHandler;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.corsConfigurationSource = corsConfigurationSource;
        this.rateLimitFilter = rateLimitFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // tells Spring Security to consult our CorsConfigurationSource
                // bean for preflight handling, instead of ignoring CORS
                // entirely (its default when nothing is configured)
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                // Stateless bearer-token API — no cookies, no browser forms
                // submitting to this backend, so there's no CSRF attack
                // surface to protect.
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // must stay open — these ARE how you obtain the
                        // credentials/token needed for everything else
                        .requestMatchers("/api/auth/register", "/api/auth/login", "/api/auth/refresh").permitAll()
                        // order matters: more specific rules must be listed
                        // before the general authenticated() catch-all below
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex
                        // Triggers (401 Unauthorized) when an unauthenticated user tries to access a protected route
                        .authenticationEntryPoint(authenticationEntryPoint)
                        // Triggers (403 Forbidden) when an authenticated user lacks the required roles/permissions
                        .accessDeniedHandler(accessDeniedHandler)
                )
                // no session, ever — every request authenticates itself
                // independently via JwtAuthenticationFilter below
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // Spring Security orders same-position filters by registration order — registering rateLimitFilter
                // first places it ahead of jwtAuthenticationFilter in the actual chain,
                // so throttled requests never reach JWT validation at all
                .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
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