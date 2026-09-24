package com.example.workspace.auth;

public record LoginResponse(
        String accessToken,
        String refreshToken
) {
}