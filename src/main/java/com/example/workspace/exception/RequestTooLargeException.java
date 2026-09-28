package com.example.workspace.exception;

import java.io.IOException;

// Extends IOException on purpose: it's thrown from inside the request
// InputStream while Jackson is reading, and Spring's JSON converter wraps
// IOExceptions into HttpMessageNotReadableException, where
// GlobalExceptionHandler finds this in the cause chain and answers 413.
public class RequestTooLargeException extends IOException {
    public RequestTooLargeException(long limit) {
        super("Request body exceeds " + limit + " bytes");
    }
}