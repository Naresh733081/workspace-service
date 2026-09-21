package com.example.workspace.exception;

import org.springframework.http.HttpStatus;

// Single source of truth: every known API failure gets exactly one entry
// here, tying together the HTTP status, the machine-readable code a
// frontend can switch on, and a sane default human message. Add a new
// failure type here once, everything downstream picks it up automatically.
public enum ErrorCode {

    VALIDATION_ERROR(HttpStatus.BAD_REQUEST, "Request validation failed"),
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "Authentication is required to access this resource"),
    ACCESS_DENIED(HttpStatus.FORBIDDEN, "You do not have permission to access this resource"),
    RESOURCE_NOT_FOUND(HttpStatus.NOT_FOUND, "The requested resource was not found"),
    CONFLICT(HttpStatus.CONFLICT, "The resource already exists"),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "Something went wrong");

    private final HttpStatus httpStatus;
    private final String defaultMessage;

    ErrorCode(HttpStatus httpStatus, String defaultMessage) {
        this.httpStatus = httpStatus;
        this.defaultMessage = defaultMessage;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public String getDefaultMessage() {
        return defaultMessage;
    }
}