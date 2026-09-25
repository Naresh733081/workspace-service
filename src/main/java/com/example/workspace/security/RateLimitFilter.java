package com.example.workspace.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
// 1. UNBOUNDED MEMORY GROWTH: the map below never evicts entries. Every
//    distinct IP that ever hits these endpoints gets a permanent Bucket
//    object for the life of the JVM. An attacker doesn't even need to
//    defeat the rate limit — sending single requests from many different
//    (spoofed/rotating) IPs grows this map indefinitely, a memory
//    exhaustion vector independent of the throttling itself.
//
// 2. IP IS A WEAK IDENTITY: request.getRemoteAddr() is shared by everyone
//    behind the same NAT/corporate network (one bad actor can exhaust the
//    bucket for many innocent users), and trivially varied by an attacker
//    with access to multiple IPs/a proxy pool/a botnet. It's also likely
//    WRONG once this runs behind a reverse proxy (e.g. on Render) unless
//    X-Forwarded-For is parsed — which it currently is not.
//
// 3. NOT DISTRIBUTED: in-memory only. Each application instance has its
//    own bucket map. Horizontal scaling multiplies the effective allowed
//    rate by instance count.
//
// 4. NO GRADUATED RESPONSE: a legitimate user who mistypes their password
//    5 times is treated identically to an attacker — flat cutoff, no
//    CAPTCHA fallback, no distinction.
//
// None of these are fixed in this commit. This is "meaningfully better
// than nothing" for a single-instance app with no adversarial traffic
// yet — not a complete brute-force defense.
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

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

        String clientIp = request.getRemoteAddr();
        Bucket bucket = buckets.computeIfAbsent(clientIp, ip -> newBucket());

        if (bucket.tryConsume(1)) {
            filterChain.doFilter(request, response);
        } else {
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
}