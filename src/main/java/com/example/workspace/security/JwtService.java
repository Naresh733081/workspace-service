package com.example.workspace.security;

import com.example.workspace.exception.ApiException;
import com.example.workspace.exception.ErrorCode;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Service
public class JwtService {

    private final SecretKey signingKey;
    private final long accessTokenExpirationMs;

    public JwtService(@Value("${jwt.secret}") String secret,
                      @Value("${jwt.access-token-expiration-ms}") long accessTokenExpirationMs) {
        // HMAC-SHA256 needs a key of sufficient length — jjwt derives the
        // key straight from our configured secret string. In production
        // this secret is what stands between "anyone can forge a token"
        // and "only this server can issue valid tokens"
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpirationMs = accessTokenExpirationMs;
    }

    public String generateToken(String subjectEmail) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + accessTokenExpirationMs);

        return Jwts.builder()
                // subject identifies WHO this token represents — we use
                // email since that's our unique user identifier, same
                // value UserDetailsServiceImpl looks users up by
                .subject(subjectEmail)
                .issuedAt(now)
                .expiration(expiry)
                // signing (not encrypting) means the token's claims are
                // readable by anyone who decodes it — signing only proves
                // WE issued it, and it hasn't been tampered with. Never put
                // a password or anything sensitive in the claims.
                .signWith(signingKey)
                .compact();
    }

    // Parses and verifies the token in one step. jjwt checks the signature
    // AND the expiration as part of parsing itself — if either is wrong, it
    // throws before we ever get a Claims object back. We deliberately
    // collapse every failure reason (bad signature, expired, malformed) into
    // the SAME ApiException/ErrorCode. Telling a caller "the signature was
    // wrong" vs "it expired" vs "it was garbage" leaks information about
    // WHY their forged token failed — useless for a legitimate client, and
    // mildly helpful to an attacker probing the endpoint.
    public String extractSubject(String token) {
        return parseClaims(token).getSubject();
    }

    private Claims parseClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException | IllegalArgumentException ex) {
            // JwtException covers ExpiredJwtException, SignatureException,
            // MalformedJwtException — all of jjwt's failure cases share
            // this common parent, so one catch block handles all of them.
            throw new ApiException(ErrorCode.INVALID_TOKEN);
        }
    }
}