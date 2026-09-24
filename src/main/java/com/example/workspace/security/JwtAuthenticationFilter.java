package com.example.workspace.security;

import com.example.workspace.exception.ApiException;
import com.example.workspace.user.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// OncePerRequestFilter guarantees this runs exactly once per request, even
// if the request gets internally forwarded/dispatched more than once —
// important because Servlet containers can otherwise re-invoke filters.
//
// This filter's ONLY job is: if a valid bearer token is present, populate
// SecurityContext from it. It does NOT reject requests itself — an absent
// or invalid token just means this filter does nothing, and whatever
// happens next (session auth, or ultimately a 401 from authorizeHttpRequests)
// proceeds exactly as it would have before this filter existed.
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final UserDetailsServiceImpl userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsServiceImpl userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader(AUTH_HEADER);

        // no header, or not a bearer token — nothing for this filter to do.
        // We deliberately do NOT reject the request here. Someone might be
        // relying on the existing session cookie instead — that's still a
        // valid path right now, and rejecting here would break it.
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring(BEARER_PREFIX.length());

        try {
            String email = jwtService.extractSubjectForAccessToken(token);

            // Don't clobber an already-authenticated context. In practice
            // this matters less right now (a request either has a session
            // or doesn't), but it's the correct defensive check once
            // multiple authentication mechanisms coexist in one chain.
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(email);

                // this constructor (principal, credentials, authorities) is
                // the ALREADY-authenticated form — unlike the login flow's
                // UsernamePasswordAuthenticationToken(email, password),
                // there's no password here at all. Presenting a valid,
                // correctly-signed token IS the proof of identity; we don't
                // re-check a password on every request.
                var authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                // WebAuthenticationDetailsSource extracts network metadata (client IP address and HTTP session ID) from the
                // incoming request and attaches it to the token for auditing and framework logging.
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(authentication);
                SecurityContextHolder.setContext(context);
            }
        } catch (ApiException ex) {
            // token was present but invalid/expired/tampered. We still
            // don't throw or write a response here — we let the request
            // continue unauthenticated. authorizeHttpRequests + our
            // AuthenticationEntryPoint will reject it with a proper 401
            // further down the chain, using the SAME error-handling path
            // as "no token at all." A bad token and no token produce
            // identical, indistinguishable responses to the client.
        }

        filterChain.doFilter(request, response);
    }
}