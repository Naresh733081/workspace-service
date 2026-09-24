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
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

    // Distinguishes an access token from a refresh token INSIDE the token
    // itself. Without this, nothing stops a client from sending a refresh
    // token as a normal Authorization: Bearer header and having it
    // accepted as if it were a short-lived access token — a refresh
    // token is long-lived and shouldn't be usable to directly access
    // protected resources.
    public enum TokenType { ACCESS, REFRESH }

    public record IssuedToken(String token, Instant expiresAt) {}

    private static final String ISSUER = "workspace-backend";
    private static final String CLAIM_TOKEN_TYPE = "type";

    private final SecretKey signingKey;
    private final long accessTokenExpirationMs;
    private final long refreshTokenExpirationMs;

    public JwtService(@Value("${jwt.secret}") String secret,
                      @Value("${jwt.access-token-expiration-ms}") long accessTokenExpirationMs,
                      @Value("${jwt.refresh-token-expiration-ms}") long refreshTokenExpirationMs) {
        // HMAC-SHA256 needs a key of sufficient length — jjwt derives the
        // key straight from our configured secret string. In production
        // this secret is what stands between "anyone can forge a token"
        // and "only this server can issue valid tokens"
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpirationMs = accessTokenExpirationMs;
        this.refreshTokenExpirationMs = refreshTokenExpirationMs;
    }

    // kept for callers that only need the raw string (JwtAuthenticationFilter
// doesn't care about expiry metadata, only the token itself)
    public String generateAccessToken(String subjectEmail) {
        return generateAccessTokenDetailed(subjectEmail).token();
    }

    // jti is passed in (not generated internally) for refresh tokens
    // specifically, because the caller (refresh token flow)
    // needs to know the exact jti it just issued, to persist it as the
    // lookup key in the database. Generating it internally and having no
    // way to get it back out would make that impossible.
    public String generateRefreshToken(String subjectEmail, String jti) {
        return buildToken(subjectEmail, refreshTokenExpirationMs, TokenType.REFRESH, jti).token();
    }

    public IssuedToken generateAccessTokenDetailed(String subjectEmail) {
        return buildToken(subjectEmail, accessTokenExpirationMs, TokenType.ACCESS, UUID.randomUUID().toString());
    }

    public IssuedToken generateRefreshTokenDetailed(String subjectEmail, String jti) {
        return buildToken(subjectEmail, refreshTokenExpirationMs, TokenType.REFRESH, jti);
    }

    private IssuedToken buildToken(String subjectEmail, long expirationMs, TokenType type, String jti) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        String token = Jwts.builder()
                // subject identifies WHO this token represents — we use
                // email since that's our unique user identifier, same
                // value UserDetailsServiceImpl looks users up by
                .subject(subjectEmail)
                .issuer(ISSUER)
                .id(jti)
                .claim(CLAIM_TOKEN_TYPE, type.name())
                .issuedAt(now)
                .expiration(expiry)
                // signing (not encrypting) means the token's claims are
                // readable by anyone who decodes it — signing only proves
                // WE issued it, and it hasn't been tampered with. Never put
                // a password or anything sensitive in the claims.
                .signWith(signingKey)
                .compact();

        return new IssuedToken(token, expiry.toInstant());
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

    public String extractJti(String token) {
        return parseClaims(token).getId();
    }

    // Access-token validation now ALSO checks the type claim — a refresh
    // token presented here is rejected even though its signature and
    // expiration are otherwise perfectly valid. This is what actually
    // enforces the access/refresh separation; without this check, the
    // "type" claim would just be inert metadata nobody looks at.
    public String extractSubjectForAccessToken(String token) {
        Claims claims = parseClaims(token);
        requireTokenType(claims, TokenType.ACCESS);
        return claims.getSubject();
    }

    public Claims extractClaimsForRefreshToken(String token) {
        Claims claims = parseClaims(token);
        requireTokenType(claims, TokenType.REFRESH);
        return claims;
    }

    private void requireTokenType(Claims claims, TokenType expected) {
        String actual = claims.get(CLAIM_TOKEN_TYPE, String.class);
        if (!expected.name().equals(actual)) {
            // same ErrorCode as every other JWT failure — a wrong-type
            // token isn't a case worth telling the caller apart from
            // "invalid token" in general
            throw new ApiException(ErrorCode.INVALID_TOKEN);
        }
    }

    private Claims parseClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(signingKey)
                    .requireIssuer(ISSUER)
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