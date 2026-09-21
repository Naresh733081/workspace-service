package com.example.workspace.security;

import com.example.workspace.exception.ApiError;
import com.example.workspace.exception.ErrorCode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

// Called specifically when an ALREADY-authenticated request fails an
// authorization check (e.g. wrong role). Different extension point from
// AuthenticationEntryPoint on purpose — that one fires when there's no
// identity at all, this one fires when there IS an identity, but it isn't
// permitted. Keeping them separate keeps the 401-vs-403 distinction honest
// in the code, not just in the response body.
@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        ApiError body = ApiError.of(ErrorCode.ACCESS_DENIED, request.getRequestURI());

        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}