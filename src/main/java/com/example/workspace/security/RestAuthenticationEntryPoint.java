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

    // We need this because this code runs early in the security chain,
    // so Spring's automatic JSON converter isn't available yet.
    // findAndRegisterModules() is required so Jackson can handle
    // modern Java 8 types like 'Instant' without crashing.
    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        ApiError body = ApiError.of(ErrorCode.UNAUTHORIZED, request.getRequestURI());

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}