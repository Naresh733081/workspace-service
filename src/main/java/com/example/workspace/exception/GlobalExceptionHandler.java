package com.example.workspace.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiError> handleApiException(ApiException ex, HttpServletRequest request) {
        ApiError body = ApiError.of(ex.getErrorCode(), ex.getMessage(), request.getRequestURI());

        // Expected, known failure categories — logged at WARN, not ERROR.
        // An INVALID_TOKEN or RESOURCE_NOT_FOUND isn't a bug in our code,
        // it's a normal outcome of normal usage (an expired session, a
        // bad guess at a URL). Logging these as ERROR would bury genuine
        // application bugs under routine noise, making log review useless.
        log.warn("API exception: code={} status={} path={} message={}",
                ex.getErrorCode(), ex.getErrorCode().getHttpStatus().value(),
                request.getRequestURI(), ex.getMessage());

        return ResponseEntity.status(ex.getErrorCode().getHttpStatus()).body(body);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex, HttpServletRequest request) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(err -> err.getField() + ": " + err.getDefaultMessage())
                .findFirst()
                .orElse(ErrorCode.VALIDATION_ERROR.getDefaultMessage());

        ApiError body = ApiError.of(ErrorCode.VALIDATION_ERROR, message, request.getRequestURI());

        // validation failures are routine client-input noise, not even
        // worth a WARN — INFO is enough to have a record without it
        // looking alarming in a log dashboard
        log.info("Validation failed: path={} message={}", request.getRequestURI(), message);

        return ResponseEntity.status(ErrorCode.VALIDATION_ERROR.getHttpStatus()).body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleGeneric(Exception ex, HttpServletRequest request) {
        ApiError body = ApiError.of(ErrorCode.INTERNAL_ERROR, request.getRequestURI());

        // this branch means something we did NOT anticipate happened —
        // a real bug, a downstream failure, something worth waking
        // someone up for in a real production alerting setup. ERROR, with
        // the full exception (stack trace and all) — this is exactly the
        // detail we refuse to send to the CLIENT (see ApiError.of above,
        // generic message only) but absolutely want for ourselves.
        log.error("Unhandled exception: path={}", request.getRequestURI(), ex);

        return ResponseEntity.status(ErrorCode.INTERNAL_ERROR.getHttpStatus()).body(body);
    }
}