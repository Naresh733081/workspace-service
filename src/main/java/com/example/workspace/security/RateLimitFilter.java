package com.example.workspace.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

// Per-IP token bucket, in-memory, applied only to the two endpoints that
// are actually brute-forceable (login, register). This is a real but
// DELIBERATELY LIMITED first pass — known flaws, accepted for now:
//
// 1. IP IS A WEAK IDENTITY: request.getRemoteAddr() is shared by everyone
//    behind the same NAT/corporate network (one bad actor can exhaust the
//    bucket for many innocent users), and trivially varied by an attacker
//    with access to multiple IPs/a proxy pool/a botnet. It's also likely
//    WRONG once this runs behind a reverse proxy (e.g. on Render) unless
//    X-Forwarded-For is parsed — which it currently is not.
//
// 2. NOT DISTRIBUTED: in-memory only. Each application instance has its
//    own bucket map. Horizontal scaling multiplies the effective allowed
//    rate by instance count.
//
// 3. NO GRADUATED RESPONSE: a legitimate user who mistypes their password
//    5 times is treated identically to an attacker — flat cutoff, no
//    CAPTCHA fallback, no distinction.
//
// None of these are fixed in this commit. This is "meaningfully better
// than nothing" for a single-instance app with no adversarial traffic
// yet — not a complete brute-force defense.
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    // Bounded + self-evicting: entries drop out after 2 minutes of no
    // access (comfortably longer than our 1-minute window, so an actively
    // abusive IP's bucket survives long enough to matter), and a hard
    // maximum size means even a deliberate flood of distinct fake IPs
    // can't grow this past a fixed ceiling. The original
    // ConcurrentHashMap had neither property.
    private final Cache<String, Bucket> buckets = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofMinutes(2))
            .maximumSize(10_000)
            .build();

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();

        // only these two — an authenticated user hitting /api/notes
        // repeatedly is normal usage, not something to throttle
        if (!path.equals("/api/auth/login") && !path.equals("/api/auth/register")) {
            filterChain.doFilter(request, response);
            return;
        }

        // still the real client IP only in the absence of a reverse proxy —
        // unresolved, see class comment
        String clientIp = normalizeClientIp(request);
        Bucket bucket = buckets.get(clientIp, ip -> newBucket());

        if (bucket.tryConsume(1)) {
            filterChain.doFilter(request, response);
        } else {
            log.warn("Rate limit exceeded: ip={} path={}", clientIp, path);

            response.setStatus(429);
            response.setContentType("application/json");
            response.getWriter().write(
                    "{\"status\":429,\"error\":\"RATE_LIMITED\",\"message\":\"Too many requests, please try again later\"}"
            );
        }
    }

    private Bucket newBucket() {
        // 5/minute per IP — generous for a real user's typo, restrictive
        // enough to make naive brute-forcing impractical
        Bandwidth limit = Bandwidth.classic(5, Refill.greedy(5, Duration.ofMinutes(1)));
        return Bucket.builder().addLimit(limit).build();
    }

    // Normalize loopback addresses so local requests are treated as the same client.
    // Depending on the server, localhost can appear as 127.0.0.1 (IPv4) or ::1 (IPv6).
    // This prevents separate rate-limit buckets from being created for the same local client.
    private String normalizeClientIp(HttpServletRequest request) {
        String ip = request.getRemoteAddr();

        if ("127.0.0.1".equals(ip)
                || "::1".equals(ip)
                || "0:0:0:0:0:0:0:1".equals(ip)) {
            return "localhost";
        }

        return ip;
    }
}