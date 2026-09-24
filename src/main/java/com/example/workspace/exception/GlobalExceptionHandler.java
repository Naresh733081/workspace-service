package com.example.workspace.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.sql.SQLException;

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

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ApiError> handleDataAccess(DataAccessException ex, HttpServletRequest request) {
        // Spring wraps the real driver exception several layers deep. We walk
        // the cause chain explicitly to pull out the actual SQLState + message
        // instead of relying on the top-level message, which is often a
        // generic phrase like "could not execute statement" — see the
        // demonstration that motivated this commit.
        String sqlState = null;
        String rootMessage = ex.getMessage();

        Throwable cause = ex;
        while (cause != null) {
            if (cause instanceof SQLException sqlEx) {
                sqlState = sqlEx.getSQLState();
                rootMessage = sqlEx.getMessage();
                break;
            }
            cause = cause.getCause();
        }

        // structured, filterable fields — sqlState and rootMessage are
        // separate arguments, not smashed into one string, so a log
        // aggregator (or a future DB-backed log table) can query on them
        // independently, e.g. "every failure with sqlState=23502"
        log.error("Database exception: path={} sqlState={} message={}",
                request.getRequestURI(), sqlState, rootMessage, ex);

        // client still gets our generic shape — a raw SQL error message is
        // exactly the kind of internal detail we never
        // expose over HTTP
        ApiError body = ApiError.of(ErrorCode.INTERNAL_ERROR, request.getRequestURI());
        return ResponseEntity.status(ErrorCode.INTERNAL_ERROR.getHttpStatus()).body(body);
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