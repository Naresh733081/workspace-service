package com.example.workspace.security;

import com.example.workspace.exception.ApiError;
import com.example.workspace.exception.ErrorCode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

// Spring Security calls this specifically when an unauthenticated request
// hits a route that requires authentication. This runs INSIDE the security
// filter chain, before Spring MVC/DispatcherServlet ever sees the request —
// which is exactly why @RestControllerAdvice can't handle this case; there's
// no controller invocation for it to wrap around.
@Component
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;
    private static final Logger log = LoggerFactory.getLogger(RestAuthenticationEntryPoint.class);

    // Inject Spring's own autoconfigured ObjectMapper instead of building
    // a new one by hand. This is the exact same instance Spring uses to
    // serialize every normal controller response and every
    // GlobalExceptionHandler response — using it here guarantees identical
    // formatting (ISO-8601 timestamps, same naming strategy, etc.) instead
    // of two independently-configured JSON serializers quietly drifting
    // apart, which is exactly the bug we just hit.
    public RestAuthenticationEntryPoint(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        ApiError body = ApiError.of(ErrorCode.UNAUTHORIZED, request.getRequestURI());

        // authException.getMessage() here is safe to log (server-side only) —
        // this is exactly the kind of internal detail Commit 014 deliberately
        // kept OUT of the client-facing ApiError, but it's genuinely useful
        // for us to have server-side
        log.warn("Authentication failed: path={} reason={}", request.getRequestURI(), authException.getMessage());

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}