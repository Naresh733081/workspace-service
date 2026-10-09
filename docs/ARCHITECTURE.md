# Architecture decisions

Written for someone using this repo as a starting point for their own
project. For each significant piece: what problem it solves, what we
chose, what we considered instead, and — since you'll probably want to
change or remove some of these — where to look if you do.

## Authentication: stateless JWT, not sessions

We built session-based auth first (see `docs/adr/001-session-vs-jwt.md`),
then deliberately moved to JWT once a separate frontend origin and
possible multi-instance deployment became the target. **If your project
is a single-instance, same-origin, browser-rendered app, session auth is
simpler and arguably a better default** — cookies get `HttpOnly` for free,
which a JS-held JWT does not. Don't copy the JWT machinery reflexively;
read that ADR and decide for your own case.

To rip out JWT and go back to sessions: delete `JwtService`,
`JwtAuthenticationFilter`, the refresh token classes, and
`SessionCreationPolicy.STATELESS` in `SecurityConfig`; restore the
`HttpSessionSecurityContextRepository` code from the login method (git log
for "session based authentication" to find it).

## Error handling: ErrorCode enum + ApiException, not per-case exceptions

Every API failure maps through one enum (`ErrorCode`) that ties together
an HTTP status, a machine-readable string, and a default message. The
alternative — a custom exception class per failure type
(`NoteNotFoundException`, `UserNotFoundException`, ...) — is what we
started with and deliberately abandoned: it doesn't scale past a couple of
resource types, and it's easy for two exceptions to accidentally return
different statuses for what's conceptually the same failure.

To add a new failure type: add one line to `ErrorCode`, throw
`new ApiException(ErrorCode.YOUR_CODE, "specific message")` anywhere in
the app. You never need a new exception class or a new handler method.

## Rate limiting: in-memory per-IP, not Redis

Deliberately simple, deliberately limited — full writeup and every known
flaw is in the comment block at the top of `RateLimitFilter.java` and
`docs/adr/002-rate-limiting.md`. Short version: IP is a weak identity,
this doesn't work correctly behind a reverse proxy without
`X-Forwarded-For` parsing (which we don't do), and it isn't distributed
across multiple instances. Fine for one instance with no adversarial
traffic yet. If you deploy behind Render/a load balancer or scale past one
instance, revisit this before trusting it.

To remove entirely: delete `RateLimitFilter.java`, remove its bean/filter
registration in `SecurityConfig`, drop the Bucket4j and Caffeine
dependencies from `pom.xml`.

## Refresh tokens: rotation, not indefinite reuse

Every refresh issues a brand new access+refresh pair and revokes the old
refresh token. This means a stolen-and-reused refresh token is detectable
(the legitimate user's next refresh will fail, since their token was
already consumed) — but we don't currently act on that detection beyond
rejecting the reuse. A more complete implementation would revoke the
*entire token family* on detected reuse, forcing a real login. We didn't
build that — no email/alerting infrastructure exists yet to notify a user
their account may be compromised, so a silent family-revocation wouldn't
even be visible to them. Worth adding if you build notifications.

To remove refresh tokens entirely: delete `RefreshToken`,
`RefreshTokenRepository`, `RefreshTokenCleanupJob`, the `/api/auth/refresh`
endpoint, and the `TokenType`/`jti` machinery in `JwtService` — access
tokens alone (with re-login on expiry) are a legitimate simpler choice for
a smaller project.

## Request size limits: a custom filter, not a Spring property

There's no built-in Spring Boot property that caps a plain JSON body size
on Tomcat — `spring.servlet.multipart.*` only covers file uploads. Hence
`RequestSizeLimitFilter`, which checks `Content-Length` when present and
counts actual bytes read otherwise (catching chunked requests). If you
switch to Undertow, its `server.undertow.max-http-post-size` property
covers this natively and the filter becomes unnecessary.

## Actuator: locked to health only by default

`/actuator/health` is public (deployment platforms need it, unauthenticated).
Everything else requires `ROLE_ADMIN` AND must be explicitly added to
`management.endpoints.web.exposure.include` — two independent locks, both
have to be changed to expose something new. `heapdump` and `shutdown` are
never enabled, anywhere — a heap dump contains the JWT secret and password
hashes in live memory.

## Schema management: manual SQL, no Flyway/Liquibase

Every table's DDL lives in the git history of the commit that introduced
it (search commit messages for the table name), applied by hand via
`psql`. This was a deliberate choice for this project (see the early
commits' reasoning) — **for a real team project, use Flyway or Liquibase
instead.** Manual schema management doesn't scale past one developer
without a lot of discipline and communication. If you adopt this repo as
a base, this is probably the first thing to change.

## Logging: SLF4J to stdout, not a database table

Every failure logs at a level matching its actual severity (WARN for
expected auth/validation failures, ERROR only for genuinely unexpected
exceptions, with full stack traces reserved for ERROR). Nothing is
persisted to the database — see the reasoning in the commit that added
structured logging: writing failures to the same database that's already
under load, inside the same request path that's already failing, is a
real anti-pattern. If you need a durable, queryable audit trail, build it
as an async/best-effort write, separate from the request path.

## What we explicitly decided NOT to build

- **Account lockout** — real DoS-against-a-victim tradeoff, no
  notification infrastructure to make it safe. Revisit if you add email.
- **CAPTCHA / graduated rate-limit response** — more infrastructure than
  this project's scope justified.
- **Distributed rate limiting (Redis)** — no need until multi-instance.
- **A generic permission framework beyond role checks** — `hasRole("ADMIN")`
  was enough for this app's one admin route; don't build more than you need.

## How to use this repo as a starting point

1. Read `docs/adr/*.md` first — they're short and explain *why*, not just *what*.
2. Decide session vs. JWT for your actual deployment shape before keeping our choice by default.
3. Decide whether you need refresh tokens at all — many apps don't.
4. Replace manual schema management with Flyway/Liquibase unless you have a specific reason not to.
5. Everything else (ErrorCode, structured logging, security headers, request size limits) is broadly reusable as-is for most Spring Boot APIs.