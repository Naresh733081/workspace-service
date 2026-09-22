package com.example.workspace.security;

import com.example.workspace.exception.ApiException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private final JwtService jwtService = new JwtService(
            "test-secret-key-for-unit-tests-only-not-used-anywhere-real",
            3600000
    );

    @Test
    void validTokenReturnsOriginalSubject() {
        String token = jwtService.generateToken("test@example.com");
        assertEquals("test@example.com", jwtService.extractSubject(token));
    }

    @Test
    void tamperedTokenIsRejected() {
        String token = jwtService.generateToken("test@example.com");
        String tampered = token.substring(0, token.length() - 2) + "xx";

        assertThrows(ApiException.class, () -> jwtService.extractSubject(tampered));
    }

    @Test
    void malformedTokenIsRejected() {
        assertThrows(ApiException.class, () -> jwtService.extractSubject("not-a-real-jwt"));
    }

    @Test
    void expiredTokenIsRejected() {
        // expiration set to a duration that's already in the past
        JwtService shortLivedService = new JwtService(
                "test-secret-key-for-unit-tests-only-not-used-anywhere-real",
                -1000
        );
        String token = shortLivedService.generateToken("test@example.com");

        assertThrows(ApiException.class, () -> shortLivedService.extractSubject(token));
    }
}