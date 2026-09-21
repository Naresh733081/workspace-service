package com.example.workspace.exception;

// One exception type for every known API failure, instead of a new class
// per failure case. The ErrorCode carries the HTTP status + default message;
// this just optionally overrides the message with request-specific detail.
public class ApiException extends RuntimeException {

    private final ErrorCode errorCode;

    public ApiException(ErrorCode errorCode) {
        super(errorCode.getDefaultMessage());
        this.errorCode = errorCode;
    }

    public ApiException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }
}