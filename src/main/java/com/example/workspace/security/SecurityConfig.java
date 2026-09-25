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
                .headers(headers -> headers
                        // ── X-Content-Type-Options: nosniff ──────────────────
                        // Without this, some older browsers will try to
                        // "guess" a response's content type by sniffing its
                        // bytes, ignoring the Content-Type header we actually
                        // sent. This matters because an attacker who can get
                        // us to serve THEIR data (e.g. an uploaded file)
                        // could craft bytes that look like they start with
                        // "<script>" and get a browser to execute it as HTML/
                        // JS even though we declared it as e.g.
                        // "application/json" or "image/png". This header
                        // forces the browser to trust our declared
                        // Content-Type and never guess. Spring Security
                        // enables this by default already — we're setting it
                        // explicitly so it's a documented decision, not a
                        // silent default.
                        .contentTypeOptions(contentTypeOptions -> {
                        })

                        // ── X-Frame-Options: DENY ────────────────────────────
                        // Prevents this API's responses from being rendered
                        // inside an <iframe> on another site. This defends
                        // against clickjacking — an attacker embedding an
                        // invisible iframe of an authenticated page over a
                        // fake UI, tricking a logged-in user into clicking
                        // something they didn't mean to. We're a JSON API,
                        // not HTML pages meant to be viewed directly, so
                        // there is genuinely no legitimate reason for any
                        // response from this backend to ever be framed.
                        // DENY (not SAMEORIGIN) because there's no frontend
                        // page served BY this backend that would need to
                        // frame itself.
                        .frameOptions(frameOptions -> frameOptions.deny())

                        // ── Strict-Transport-Security ────────────────────────
                        // Tells the browser: for the next `maxAgeInSeconds`,
                        // NEVER attempt to reach this host over plain HTTP
                        // again, even if the user types http:// or clicks an
                        // http:// link — force HTTPS automatically, before
                        // even making the request. This defends against SSL-
                        // stripping attacks, where a network-level attacker
                        // (e.g. on public wifi) intercepts an initial HTTP
                        // request before it gets upgraded to HTTPS. Only
                        // meaningful once actually deployed behind HTTPS
                        // (Render provides this) — harmless locally over
                        // plain http on localhost, browsers ignore HSTS
                        // headers received over non-HTTPS connections.
                        // includeSubDomains extends the same protection to
                        // any subdomain of the deployed host.
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31536000) // 1 year
                        )

                        // ── Referrer-Policy: strict-origin-when-cross-origin ─
                        // Controls what gets sent in the Referer header when a
                        // browser navigates AWAY from a page served by this
                        // API to somewhere else (relevant mainly for any
                        // static/error pages this backend might ever serve
                        // directly, and for outbound links in something like
                        // a password reset email later). Prevents leaking
                        // full URLs — which could contain query params, IDs,
                        // or tokens if a mistake was ever made and one ended
                        // up in a URL — to third-party destinations. This is
                        // the modern, balanced default recommended by OWASP:
                        // full URL on same-origin navigation, origin only
                        // (no path/query) cross-origin, nothing at all on a
                        // downgrade from HTTPS to HTTP.
                        .referrerPolicy(referrer -> referrer
                                .policy(org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                        )

                        // ── Cache-Control on sensitive responses ─────────────
                        // Spring Security's default header writer already adds
                        // Cache-Control: no-cache, no-store, must-revalidate
                        // on every response by default — preventing a shared
                        // proxy or the browser's disk cache from persisting a
                        // response that might contain a token or personal
                        // data (e.g. GET /api/auth/me, GET /api/notes). We're
                        // not overriding this — Spring's default here is
                        // already correct — just noting explicitly that this
                        // is active and why, rather than leaving it as an
                        // unexplained default.
                        .cacheControl(cache -> {
                        })
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