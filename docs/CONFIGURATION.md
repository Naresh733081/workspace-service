# Configuration reference

Everything this app reads from `application.properties` / profile files /
environment variables, in one place. If you're stripping this project down
for a different use case, this is the file to check before deleting a
class — see ARCHITECTURE.md for what each piece is actually *for*.

## Environment variables (must be set for the app to start)

These are placeholders in `application.properties` (`${VAR_NAME}`), which
means the app refuses to start if they're missing — on purpose (see
ARCHITECTURE.md, "fail loud vs fail silent"). Set them as real OS
environment variables, your IDE's run configuration, or your hosting
platform's environment settings. **Never put real values in a committed
file.**

| Variable | Used for | Example (local) | Notes |
|---|---|---|---|
| `DATABASE_URL` | JDBC connection string | `jdbc:postgresql://localhost:5432/workspace` | |
| `DATABASE_USERNAME` | DB user | `postgres` | |
| `DATABASE_PASSWORD` | DB password | `postgres` | never commit a real one |
| `JWT_SECRET` | signs/verifies every JWT | any long random string locally | production: `openssl rand -base64 32` |
| `JWT_ACCESS_TOKEN_EXPIRATION_MS` | access token lifetime | `3600000` (1 hour) | |
| `JWT_REFRESH_TOKEN_EXPIRATION_MS` | refresh token lifetime | `1209600000` (14 days) | |

## Spring profile (must be set, or the app won't start)

| Variable | Values | What it controls |
|---|---|---|
| `SPRING_PROFILES_ACTIVE` | `local` or `prod` | log verbosity, actuator exposure list, CORS allowed origin (see `CorsConfig.java`) |

The app deliberately has no default profile — see ARCHITECTURE.md,
"why there's no default profile."

## Properties with safe defaults (in `application.properties`, no env var needed)

These are plain configuration, not secrets — readable in the repo, and
meant to be edited directly rather than overridden per-environment. See
ARCHITECTURE.md for why each exists.

| Property | Default | What it does |
|---|---|---|
| `app.cleanup.refresh-tokens.cron` | `0 0 3 * * *` | when the refresh-token cleanup job runs (Spring cron, 6 fields) |
| `app.cleanup.refresh-tokens.retention` | `P1D` | how long an expired refresh token row is kept before deletion (ISO-8601 duration) |
| `app.limits.max-request-body` | `1MB` | JSON request body cap, enforced by `RequestSizeLimitFilter` |
| `server.tomcat.max-http-form-post-size` | `8KB` | cap for HTML form posts (we don't use these; kept small deliberately) |
| `server.max-http-request-header-size` | `8KB` | Spring Boot's own default, stated explicitly |
| `spring.servlet.multipart.enabled` | `false` | off until a file-upload endpoint exists — see ARCHITECTURE.md |
| `management.endpoints.web.exposure.include` | `health` (base) / more per profile | which actuator endpoints exist at all |
| `management.endpoint.health.show-details` | `never` (base) | whether `/actuator/health` shows component detail |

## What's hardcoded in Java, not configuration

| Where | What | Why it's in code, not properties |
|---|---|---|
| `CorsConfig.java` | allowed frontend origins, per profile | public URLs, not secrets — see ARCHITECTURE.md |
| `RateLimitFilter.java` | 5 requests/minute per IP | a security threshold, not something to tune per-deploy |
| `AuthController.java` | none currently (account lockout was considered, not implemented) | |

## Database schema

Schema is managed manually — `spring.jpa.hibernate.ddl-auto=none`, always.
There is no migration tool (Flyway/Liquibase) in this project by design
(see ARCHITECTURE.md). Every table's `CREATE`/`ALTER` statement is in the
commit that introduced it — search git log for the table name if you need
to reconstruct the schema from scratch.