package com.example.workspace.exception;

import java.time.Instant;

public record ApiError(
        Instant timestamp,
        int status,
        String error,
        String message,
        String path
) {
    // use the enum's own default message — for failures where there's
    // nothing case-specific to say (e.g. ACCESS_DENIED)
    public static ApiError of(ErrorCode code, String path) {
        return new ApiError(Instant.now(), code.getHttpStatus().value(), code.name(), code.getDefaultMessage(), path);
    }

    // override the message for cases where context matters
    // (e.g. "Note not found: 5" instead of the generic default)
    public static ApiError of(ErrorCode code, String message, String path) {
        return new ApiError(Instant.now(), code.getHttpStatus().value(), code.name(), message, path);
    }
}