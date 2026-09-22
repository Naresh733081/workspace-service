package com.example.workspace.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

// Responsible for ONE thing at this stage: turning an authenticated
// identity into a signed token. Validating a token that comes back in on
// a later request is a genuinely separate responsibility
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
}