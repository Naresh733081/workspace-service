package com.example.workspace.security;

import com.example.workspace.exception.ApiError;
import com.example.workspace.exception.ErrorCode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}