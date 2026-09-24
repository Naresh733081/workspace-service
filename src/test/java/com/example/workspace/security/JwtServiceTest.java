package com.example.workspace.security;

import com.example.workspace.exception.ApiException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private final JwtService jwtService = new JwtService(
            "test-secret-key-for-unit-tests-only-not-used-anywhere-real",
            3600000,
            1209600000
    );

    @Test
    void validAccessTokenReturnsOriginalSubject() {
        String token = jwtService.generateAccessToken("test@example.com");
        assertEquals("test@example.com", jwtService.extractSubjectForAccessToken(token));
    }

    @Test
    void refreshTokenRejectedAsAccessToken() {
        String refreshToken = jwtService.generateRefreshToken("test@example.com", "some-jti");
        // this is the check that actually matters — a refresh token must
        // not work as a bearer access token
        assertThrows(ApiException.class, () -> jwtService.extractSubjectForAccessToken(refreshToken));
    }

    @Test
    void tamperedTokenIsRejected() {
        String token = jwtService.generateAccessToken("test@example.com");
        String tampered = token.substring(0, token.length() - 2) + "xx";
        assertThrows(ApiException.class, () -> jwtService.extractSubjectForAccessToken(tampered));
    }

    @Test
    void malformedTokenIsRejected() {
        assertThrows(ApiException.class, () -> jwtService.extractSubjectForAccessToken("not-a-real-jwt"));
    }

    @Test
    void expiredTokenIsRejected() {
        JwtService shortLivedService = new JwtService(
                "test-secret-key-for-unit-tests-only-not-used-anywhere-real",
                -1000,
                1209600000
        );
        String token = shortLivedService.generateAccessToken("test@example.com");
        assertThrows(ApiException.class, () -> shortLivedService.extractSubjectForAccessToken(token));
    }
}