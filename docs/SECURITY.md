# Security Architecture — In-Depth Notes

This document exists because a git log full of "why" comments is still
scattered across thirty-plus commits. This is the same reasoning,
gathered in one place, written the way I'd explain it to a teammate
sitting next to me — not a spec, not marketing copy for the design,
just: here's the problem, here's what we picked, here's what else we
considered, here's what it would look like if we'd built this five years
ago on Java 8, and here's where it's still weak.

Read this top to bottom once, then use it as a reference. Every section
follows the same shape:

- **The problem** — what breaks without this
- **What we built** — the actual mechanism
- **Alternatives we considered** — and why we didn't pick them
- **Java 17 vs Java 8** — what changes if you're stuck on an older JDK
- **Where this is weak** — because pretending otherwise helps no one

---

## Table of contents

1. [Password storage](#1-password-storage)
2. [The authentication call chain](#2-the-authentication-call-chain)
3. [Sessions vs JWT — the actual tradeoff](#3-sessions-vs-jwt--the-actual-tradeoff)
4. [JWT structure and signing](#4-jwt-structure-and-signing)
5. [Access + refresh tokens](#5-access--refresh-tokens)
6. [The Spring Security filter chain](#6-the-spring-security-filter-chain)
7. [Authorization — roles vs the alternatives](#7-authorization--roles-vs-the-alternatives)
8. [Resource ownership vs authorization](#8-resource-ownership-vs-authorization)
9. [CORS](#9-cors)
10. [CSRF](#10-csrf)
11. [Rate limiting](#11-rate-limiting)
12. [Security response headers](#12-security-response-headers)
13. [Error handling and information leakage](#13-error-handling-and-information-leakage)
14. [Actuator exposure](#14-actuator-exposure)
15. [Request size limits](#15-request-size-limits)
16. [Secrets management](#16-secrets-management)
17. [Logging as a security control](#17-logging-as-a-security-control)
18. [Java 17 language features used, and their Java 8 equivalents](#18-java-17-language-features-used-and-their-java-8-equivalents)
19. [Decision summary table](#19-decision-summary-table)

---

## 1. Password storage

### The problem

If a database leaks — and eventually, somewhere, one does — the
consequence should be "attacker has a pile of hashes to grind through,"
not "attacker has everyone's password." Storing plaintext, or storing a
plain unsalted hash, turns a data breach into a password breach for
every account, including whatever other sites the same password is used
on. Most people reuse passwords. This isn't a defense against a
sophisticated attacker specifically targeting this app; it's a defense
against the far more common case of a breach dump getting cross-checked
against a hundred other sites.

### What we built

BCrypt, via `BCryptPasswordEncoder`:

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

BCrypt does two things a plain hash function (MD5, SHA-256, SHA-512)
does not:

- **It salts automatically.** Every call to `encode()` generates a fresh
  random salt and embeds it in the output string. Two users with the
  same password get completely different stored hashes. Without a salt,
  an attacker can precompute a rainbow table once and use it against
  every row in every leaked database that used the same hash function.
- **It's deliberately slow, and the slowness is tunable.** BCrypt takes a
  "cost factor" (`BCryptPasswordEncoder`'s default is 10, meaning 2^10
  rounds). A fast hash like SHA-256 is *designed* to be fast — that's
  perfect for checksumming a file, and terrible for password hashing,
  because it means an attacker with a GPU can try billions of guesses
  per second against a leaked hash. BCrypt costs milliseconds per guess
  by design, which turns billions of guesses per second into thousands.

The stored value looks like:

```
$2a$10$N9qo8uLOickgx2ZMRZoMye1J8O9pjLIcHkTIgtSJhYYKGxTKS0hqi
```

Breaking that down: `$2a$` is the algorithm identifier, `10` is the cost
factor, the next 22 characters are the salt, and the rest is the actual
hash. All of that is stored together in one column — there's no separate
"salt" column, because BCrypt's own format carries it.

### Alternatives we considered

**PBKDF2** (`Pbkdf2PasswordEncoder` in Spring Security). NIST-approved,
FIPS-compliant, which matters if you're in a regulated industry that
requires FIPS certification (BCrypt is not a NIST-approved algorithm).
The tradeoff: PBKDF2's slowness comes purely from iteration count against
a simple hash function, which means it's efficiently parallelizable on a
GPU or ASIC. BCrypt's design is deliberately harder to parallelize on
custom hardware. If you don't have a specific FIPS requirement, BCrypt or
Argon2 are the more commonly recommended choices today.

**Argon2** (`Argon2PasswordEncoder`, needs the `bouncycastle` dependency
in Spring Security). This is the winner of the 2015 Password Hashing
Competition and is generally considered the strongest modern choice — it
lets you tune not just CPU cost but *memory* cost, which makes GPU/ASIC
cracking meaningfully harder than BCrypt (those devices have lots of
compute but comparatively little fast memory per core). We didn't pick
it mainly because BCrypt is the more battle-tested default in the Spring
ecosystem, has zero extra dependencies (it's built into
`spring-security-crypto`), and the marginal security gain over BCrypt for
this project's threat model doesn't justify the extra dependency and
tuning surface. For a new project today with no legacy constraint,
Argon2 is a completely reasonable, arguably better, first choice.

**SCrypt** (`SCryptPasswordEncoder`). Similar memory-hardness motivation
to Argon2, older, less commonly recommended today than Argon2 specifically
because Argon2 was designed partly in response to lessons learned from
SCrypt. Not a wrong choice, just not the current best-practice default.

**Rolling your own** (salt + SHA-256 by hand). Never do this. It's not
that the concept is wrong, it's that "cost factor" and "resistance to
custom hardware" are subtle enough that a hand-rolled version will almost
certainly be weaker than any of the above, and there's no reason to take
that risk when a correct, audited implementation is one dependency away.

### Java 17 vs Java 8

This particular piece of code doesn't actually change between Java 8 and
17 — `BCryptPasswordEncoder` has looked the same since Spring Security 4.
The interesting difference is in how you'd typically *wire* the bean.

Java 17, what we wrote:

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

Java 8, functionally identical, no difference at all — this code
predates most of the syntax features that changed. The one place Java 8
would look different is if you wanted to build a small value object
around a password check result. In Java 17 we'd reach for a record:

```java
// Java 17
public record PasswordCheckResult(boolean matches, boolean needsRehash) {}
```

In Java 8, the same thing needs the full boilerplate:

```java
// Java 8
public final class PasswordCheckResult {
    private final boolean matches;
    private final boolean needsRehash;

    public PasswordCheckResult(boolean matches, boolean needsRehash) {
        this.matches = matches;
        this.needsRehash = needsRehash;
    }

    public boolean isMatches() { return matches; }
    public boolean isNeedsRehash() { return needsRehash; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PasswordCheckResult)) return false;
        PasswordCheckResult that = (PasswordCheckResult) o;
        return matches == that.matches && needsRehash == that.needsRehash;
    }

    @Override
    public int hashCode() {
        return Objects.hash(matches, needsRehash);
    }

    @Override
    public String toString() {
        return "PasswordCheckResult{matches=" + matches + ", needsRehash=" + needsRehash + '}';
    }
}
```

Fourteen lines of boilerplate we don't have to write or maintain, purely
because of the JDK version. This is the running theme in every Java 8
comparison in this document: nothing about *security* changes, but the
amount of code you have to read to find the security-relevant line goes
up substantially.

### Where this is weak

BCrypt's cost factor is currently whatever `BCryptPasswordEncoder`'s
default is (strength 10 as of Spring Security 6.x). Hardware gets faster
every year, and a cost factor that's appropriately slow today will be
too fast in five years. Nobody has to remember to bump this manually —
Spring Security has `DelegatingPasswordEncoder`, which stores the
algorithm identifier as a prefix (`{bcrypt}$2a$10$...`) so you can
upgrade the encoder later and still verify old hashes, then transparently
re-hash them with the new encoder on next successful login. We are not
currently using `DelegatingPasswordEncoder` — we inject
`BCryptPasswordEncoder` directly. Worth revisiting if this project has a
long lifespan.

---

## 2. The authentication call chain

### The problem

"Check if the password is right" sounds like a one-line `if` statement,
and if you only ever need to check a password once, it basically is. The
reason Spring Security's chain looks elaborate is that it's built to
support many different *ways* of proving identity (password, LDAP, OAuth,
a pre-authenticated header from a corporate SSO gateway...) through the
same pluggable pipeline, without the application code needing to know or
care which one is in play.

### What we built

```
AuthenticationManager.authenticate(token)
        ↓
ProviderManager (the real implementation behind the interface)
        ↓
tries each registered AuthenticationProvider in order
        ↓
DaoAuthenticationProvider (ours)
        ↓
UserDetailsServiceImpl.loadUserByUsername(email)
        ↓
UserRepository.findByEmail(email)
        ↓
PasswordEncoder.matches(rawPassword, storedHash)
```

Each box has exactly one job:

- `AuthenticationManager` is the thing calling code talks to. It doesn't
  know *how* authentication happens, only that it can hand off a request
  and get back either a fully-authenticated `Authentication` or an
  exception.
- `ProviderManager` is the concrete class Spring gives you when you ask
  for an `AuthenticationManager` bean. It holds a *list* of
  `AuthenticationProvider`s and tries each one until one succeeds or all
  of them fail. We only ever register one (`DaoAuthenticationProvider`),
  but the design supports many — e.g. you could add an LDAP provider
  alongside the database one, and a login attempt would try both.
- `DaoAuthenticationProvider` is the provider that knows the specific
  recipe "look the user up via `UserDetailsService`, then check the
  password via `PasswordEncoder`." "Dao" here means Data Access Object —
  it's the provider that talks to a data source, as opposed to, say, an
  LDAP-specific provider.
- `UserDetailsService` is the seam between Spring Security's generic
  world and our specific `User` entity. It has one method:
  `loadUserByUsername(String)`. We called it with an email, not a
  "username," because we don't have separate usernames — Spring
  Security's interface uses the word "username" generically to mean
  "whatever your unique identifier is."

### Alternatives we considered

**Skip `AuthenticationManager` entirely and check the password by hand
in the controller:**

```java
// what we did NOT do
User user = userRepository.findByEmail(email).orElseThrow(...);
if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
    throw new BadCredentialsException("bad password");
}
```

This would actually *work* for a project this size. It's fewer moving
parts, and for a genuinely simple app with exactly one way to log in and
no plans to ever add another, it's a defensible choice — you lose
nothing functionally. The reasons we didn't do this: first, going through
`AuthenticationManager` means `SecurityContextHolder` gets populated with
a real, correctly-typed `Authentication` object that carries authorities
— if we set that up by hand, it's easy to forget a detail (like
authorities) that a filter or `@PreAuthorize` check later depends on.
Second, and more relevant to why this project does it the "long way":
the whole point here is demonstrating what a real Spring Security setup
looks like, so a reader can drop in LDAP, OAuth, or SSO later along the
grain of the framework's design, not against it.

**Custom `AuthenticationProvider` implementing everything by hand**
(skip `UserDetailsService` + `DaoAuthenticationProvider`, write one class
that does both jobs). Also workable. The reason to keep them separate is
reuse: `UserDetailsService` is also what a JWT filter or a "current user"
helper can lean on later without duplicating the "how do I load a user"
logic. Collapsing it into one provider class means every future consumer
either depends on that provider (awkward — providers are meant to be used
by the authentication manager, not called directly) or duplicates the
lookup.

### Java 17 vs Java 8

The provider/service classes themselves are plain classes implementing
interfaces — no real syntax difference. Where it does matter is
`UserDetailsImpl`, which implements Spring Security's `UserDetails`
interface with five boolean methods that basically never return anything
but `true` for us:

Java 17 (what we wrote):

```java
@Override
public boolean isAccountNonExpired() { return true; }

@Override
public boolean isAccountNonLocked() { return true; }

@Override
public boolean isCredentialsNonExpired() { return true; }

@Override
public boolean isEnabled() { return true; }
```

This is identical in Java 8 — nothing modern here to simplify, since
these are trivial one-line method bodies either way. Where Java 17 does
help is in the constructor and equality-adjacent boilerplate if you
wanted `UserDetailsImpl` itself to be a value-style object; but because
it has to *implement an interface with many methods*, it can't be a
`record` (a record can implement interfaces, but `UserDetails` has five
methods beyond the constructor-derived ones, so you'd still write them
all out by hand regardless of Java version). This is a case where the
Java 17 feature set doesn't actually help — worth noting, because it's
not true that "newer Java always means less code."

### Where this is weak

We only ever register one `AuthenticationProvider`. If a login request's
email doesn't exist, `DaoAuthenticationProvider` throws
`UsernameNotFoundException` internally, which Spring Security by default
converts to the same `BadCredentialsException` a wrong password would
throw — this is intentional (see section 13 on error handling), not a
bug. Worth knowing if you're debugging and wondering why a "user not
found" case never surfaces as its own distinct exception type at the
controller.

---

## 3. Sessions vs JWT — the actual tradeoff

### The problem

HTTP is stateless. Once you've verified a password on request 1, request
2 arrives with no memory of request 1 unless something carries identity
forward between them. There are exactly two broad families of solution:
the server remembers (sessions), or the client carries proof with every
request (tokens).

### What we built, and why in that order

We built sessions first, then JWT, on purpose — not because sessions
were a mistake, but because understanding the traditional model makes it
obvious *why* JWT exists and what it trades away. The full writeup is in
`docs/adr/001-session-vs-jwt.md`; here's the expanded version.

**Session model:**

```
login → server creates a session, stores Authentication in it,
        server generates a random session ID, sends it as a cookie
next request → browser automatically attaches the cookie
             → server looks up the session ID in its store
             → finds the Authentication, request proceeds
```

The server is doing real work here: it's holding state, in memory or in
an external store, for every logged-in user, for as long as their
session lasts. The browser does almost nothing special — cookie handling
is automatic, which is actually a security feature (see CSRF, section
10, for the flip side of that "automatic" behavior).

**JWT model:**

```
login → server verifies credentials, builds a signed token containing
        the claims (who you are, when it expires), sends it back as
        a plain string in the response body
next request → CLIENT deliberately attaches it, usually in an
             Authorization header
             → server verifies the signature and expiry — no lookup
               anywhere, the token carries its own proof
```

The server holds nothing. Verifying a JWT is pure computation (check a
cryptographic signature, check a timestamp) — no database call, no
shared session store, no state at all. This is what "stateless" means in
this context, and it's the entire reason JWT plays nicely with multiple
backend instances behind a load balancer: any instance can verify any
token, because verification doesn't depend on which instance issued it
or any state that instance is holding.

### Alternatives we considered

**Sticky sessions** (a load balancer configured to always route a given
user's requests to the same backend instance, keyed on their session
cookie). This would let us keep sessions *and* scale horizontally.
Real projects do this. The reasons we didn't: it couples your
infrastructure layer to a specific routing strategy (if that instance
goes down, everyone stuck to it loses their session), and it doesn't
solve the cross-origin cookie friction of a separately-hosted frontend
(Vercel) and backend (Render), which was the actual deciding factor for
this project.

**Externalized session store** (Spring Session + Redis). Keep the
session *model* — cookie-based, server remembers — but move the "server
remembers" part into a shared Redis instance every backend instance can
read. This genuinely solves the multi-instance problem while keeping
`HttpOnly` cookies (a real security advantage over JWT — more below).
This is a legitimate, arguably *better* choice than JWT for many
projects, and we call this out explicitly in `ARCHITECTURE.md`. We didn't
build it here because it adds Redis as a new piece of infrastructure, and
part of this project's goal was demonstrating JWT specifically as a
learning exercise. If you're using this repo as a base for a real project
with a same-origin frontend, Spring Session + Redis is genuinely worth
evaluating before reaching for JWT by default.

**Opaque tokens** (a random string, not a JWT, stored server-side —
functionally a session, just delivered like a bearer token instead of a
cookie). This gets you the "attach it manually via header, no cookie
friction" benefit of JWT while keeping the "server can instantly revoke
it" benefit of sessions (with a JWT, revoking a specific token before its
natural expiry requires extra infrastructure — see section 5 on refresh
tokens for how we partially solved this). The tradeoff is you're back to
a database or cache lookup on every request, i.e., you've given up
statelessness. Some real systems use opaque *access* tokens with short
lifetimes specifically to get revocability, while accepting the lookup
cost. Worth knowing this exists as a middle ground.

### The concrete disadvantages of JWT we're accepting

Being honest about what we gave up:

1. **No instant revocation.** Once issued, a JWT is valid until it
   expires, full stop — the server can't reach out and un-issue it. Our
   1-hour access token expiry is the mitigation: worst case, a stolen
   token is usable for up to an hour. This is why the expiry is short.
   Refresh tokens (section 5) get a real revocation mechanism because we
   deliberately made *them* stateful (stored in the database), which is
   a bit of an admission that pure statelessness isn't actually what we
   want everywhere — just for the high-frequency access-token path.

2. **No `HttpOnly` protection.** A cookie can be marked `HttpOnly`,
   meaning JavaScript running on the page literally cannot read it — even
   if an attacker manages to inject a malicious script (XSS), they can't
   steal an `HttpOnly` cookie via `document.cookie`. A JWT held in
   `localStorage` or a JS variable (which is how a frontend typically
   has to store it, since it needs to read the token to attach it to
   requests) is fully readable by any script running on the page,
   including an injected one. This means our security model is now
   leaning more heavily on "don't have an XSS vulnerability in the
   frontend" than a cookie-based session would have needed to.

3. **Larger request size.** A session cookie is just an opaque ID,
   typically under 40 bytes. A JWT carries its claims and a signature —
   ours run a few hundred bytes. Not a real problem at our scale, just
   worth knowing the numbers aren't equivalent.

### Java 17 vs Java 8

`SessionCreationPolicy.STATELESS` is a plain enum constant — identical
in both versions. The more interesting comparison is the ADR document
itself, which in a Java 8 codebase might well have been a Confluence page
instead of a markdown file in the repo — not a language difference, but
a cultural one worth naming: putting ADRs in the repo, versioned
alongside the code they justify, is a practice that got much more common
during the same years Java itself was modernizing. Nothing stops you from
doing it on Java 8; it's just not a `pom.xml` line, it's a habit.

### Where this is weak

We chose JWT because of our *anticipated* deployment shape (separate
frontend origin, possible multi-instance scaling) — not because we ever
actually measured a real need. If this project stayed as a single
instance with a browser-rendered, same-origin frontend, sessions would
have been simpler and arguably more secure by default (the `HttpOnly`
point above). Worth re-litigating this decision if the deployment
assumptions change.

---

## 4. JWT structure and signing

### The problem

Once you've decided to hand the client a token instead of a cookie, you
need a format the client can carry around as an opaque string, and a way
for *any* backend instance to verify — without a database call — that
the token wasn't forged or tampered with.

### What we built

A JWT is three base64url-encoded segments separated by dots:
`header.payload.signature`. Decode the header and payload of any JWT (at
jwt.io, for example) and you can read them in plain text — **a JWT is
signed, not encrypted.** This is worth repeating because it surprises
people: anyone who intercepts a JWT can read every claim inside it
without needing the secret. The secret only proves the token wasn't
*altered* since it was issued. Never put a password, a credit card
number, or anything else sensitive into a JWT's claims.

Our token's payload, decoded:

```json
{
  "sub": "user@example.com",
  "iss": "workspace-backend",
  "jti": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "type": "ACCESS",
  "iat": 1727433600,
  "exp": 1727437200
}
```

- `sub` (subject) — who this token represents. We use email since it's
  our unique identifier.
- `iss` (issuer) — which system minted this token. Meaningful mainly once
  more than one system could theoretically issue tokens under the same
  secret; harmless to include now, and jjwt lets us call
  `.requireIssuer(...)` during validation for free hardening.
- `jti` (JWT ID) — a unique identifier for this specific token. This is
  what makes refresh token revocation possible (section 5) — we can't
  revoke "the JWT" itself (no server-side state, remember), but we can
  mark *this jti* as revoked in our own database and check it.
- `type` — not a standard JWT claim, ours, custom. Distinguishes an
  access token from a refresh token so one can't be used in place of the
  other.
- `iat` / `exp` — issued-at and expiration, standard claims, both Unix
  timestamps (seconds since epoch).

Signing:

```java
this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
// ...
Jwts.builder()
        .subject(subjectEmail)
        // ...
        .signWith(signingKey)
        .compact();
```

`Keys.hmacShaKeyFor` builds a symmetric key from our raw secret bytes.
"Symmetric" means the same key both signs and verifies — whoever has the
secret can do both. jjwt auto-selects HMAC-SHA256 (HS256) for a key of
our length.

### Alternatives we considered

**Asymmetric signing (RS256/ES256 — RSA or elliptic curve).** With
asymmetric signing, you have a private key (signs tokens) and a public
key (verifies them), and you can hand out the public key freely — a
separate service can verify tokens without ever being trusted to *issue*
them, because it physically can't (it only has the public half). This
matters in a microservices architecture where, say, five different
services all need to verify tokens but only one auth service should be
able to mint them. For this project, exactly one process both issues and
verifies every token, so there's no separation-of-trust problem to solve
— symmetric HMAC is simpler, faster to compute, and appropriate. If this
project ever splits into multiple services, this is the first thing to
revisit.

**A different JWT library.** We used `io.jsonwebtoken` (jjwt). The other
mainstream choice on the JVM is Nimbus JOSE + JWT
(`com.nimbusds:nimbus-jose-jwt`), which is more feature-complete (full
JOSE/JWE support — encrypted tokens, not just signed ones) and is what
Spring Security's own OAuth2 resource server support uses internally.
jjwt has a noticeably more approachable, fluent builder API
(`Jwts.builder().subject(...).signWith(...)`), which is why we picked it
for a project meant to be read and understood, not necessarily the
"more powerful" choice. If you ever need encrypted tokens (JWE, not
just signed JWS, which is what we have), Nimbus is the more natural fit.

**Auth0's `java-jwt`.** Another common choice, similar in spirit to jjwt.
No strong reason to prefer one over the other for a project this size;
jjwt's version-0.12 fluent API tipped the choice.

**PASETO** (Platform-Agnostic Security Tokens) — a newer alternative to
JWT designed specifically to remove footguns that JWT allows, most
famously the "alg: none" vulnerability, where some poorly-implemented
JWT verifiers could be tricked into accepting a token with no signature
at all because the algorithm is specified *inside the token itself* and
some libraries trusted it blindly. jjwt, and Spring Security's tooling
generally, are not vulnerable to this specific issue when used correctly
(we always specify and enforce the verification key/algorithm
ourselves rather than trusting whatever the token claims), but PASETO
removes the class of bug entirely by design. We stuck with JWT because
it's the far more widely supported standard with better tooling and
documentation, and the specific vulnerability class is a solved problem
as long as you don't let the library trust the token's self-declared
algorithm — which we don't.

### Java 17 vs Java 8

This is one of the more visible differences in the whole project. Here's
our actual token-building code:

```java
// Java 17 — what we wrote
private String buildToken(String subjectEmail, long expirationMs, TokenType type, String jti) {
    Date now = new Date();
    Date expiry = new Date(now.getTime() + expirationMs);

    return Jwts.builder()
            .subject(subjectEmail)
            .issuer(ISSUER)
            .id(jti)
            .claim(CLAIM_TOKEN_TYPE, type.name())
            .issuedAt(now)
            .expiration(expiry)
            .signWith(signingKey)
            .compact();
}
```

On Java 8, jjwt's API itself was different (this is the 0.9.x-era API,
before the fluent builder redesign) — Java 8 predates jjwt 0.12, so a
Java 8 project would typically be using jjwt 0.9.x or 0.11.x with the
older method names:

```java
// Java 8 — jjwt 0.9.x era API (also valid on Java 17, just older style)
public String buildToken(String subjectEmail, long expirationMs, String type, String jti) {
    Date now = new Date();
    Date expiry = new Date(now.getTime() + expirationMs);

    return Jwts.builder()
            .setSubject(subjectEmail)
            .setIssuer(ISSUER)
            .setId(jti)
            .claim(CLAIM_TOKEN_TYPE, type)
            .setIssuedAt(now)
            .setExpiration(expiry)
            .signWith(SignatureAlgorithm.HS256, secretKeyBytes)
            .compact();
}
```

Notice `setSubject` vs `subject`, `setIssuer` vs `issuer` — this is
jjwt's own API evolution, not a Java language feature, but it's exactly
the kind of thing that bites people copying code from different
tutorials written years apart (this is literally the bug we hit earlier
in this project — pasted code using the 0.12 fluent API against a
0.11.5 dependency in the pom, and `.subject()` didn't exist yet). Also
note `signWith(SignatureAlgorithm.HS256, secretKeyBytes)` — older jjwt
needed you to name the algorithm explicitly as a separate parameter;
`Keys.hmacShaKeyFor(...)` combined with the newer `signWith(Key)`
overload lets the library infer the right algorithm from the key's
length and type instead.

Where actual Java *language* version matters: `TokenType` is a Java enum
in both versions, unchanged. But the `record` we use for
`IssuedToken`:

```java
// Java 17
public record IssuedToken(String token, Instant expiresAt) {}
```

On Java 8, the same thing:

```java
// Java 8
public final class IssuedToken {
    private final String token;
    private final Instant expiresAt;

    public IssuedToken(String token, Instant expiresAt) {
        this.token = token;
        this.expiresAt = expiresAt;
    }

    public String token() { return token; }
    public Instant expiresAt() { return expiresAt; }

    @Override
    public boolean equals(Object o) { /* ... */ }
    @Override
    public int hashCode() { /* ... */ }
    @Override
    public String toString() { /* ... */ }
}
```

Also worth mentioning: Java 8's `java.time` package (`Instant`, `Date`
conversions) is actually already modern — `java.time` shipped *in* Java
8, replacing the old `java.util.Date`/`Calendar` mess. So our use of
`Instant` throughout this project would look identical on Java 8. The
`Date` objects you see in the JWT-building code above exist only because
jjwt's API itself expects `java.util.Date`, not because of any Java
version constraint — that's a library API choice, not a language one.

### Where this is weak

The secret is a single, static string, loaded once at startup, used for
the lifetime of the process. There's no key rotation mechanism — if the
secret is ever compromised, every token ever issued (until natural
expiry) remains valid and forgeable, and rotating the secret would
invalidate every currently-logged-in user's session simultaneously
(a real, if rare, operational event). A more mature setup uses a `kid`
(key ID) claim in the JWT header and supports multiple valid signing
keys simultaneously, so you can introduce a new key, let old tokens
expire naturally, and retire the old key without a flag day. Not built
here — genuinely more infrastructure than this project's current scope
justifies, but worth knowing the gap exists.

---

## 5. Access + refresh tokens

### The problem

Short-lived tokens are safer (a stolen one has a small blast radius) but
annoying (users get logged out constantly). Long-lived tokens are
convenient but dangerous if stolen. The standard resolution: use both. A
short-lived access token for every actual API call, and a long-lived
refresh token whose only job is "trade me for a new access token,"
presented far less often and specifically revocable.

### What we built

```
login → access token (1 hour) + refresh token (14 days, persisted server-side by jti)
access token expires → client calls /api/auth/refresh with the refresh token
                     → server checks it's a REFRESH-type token, checks the
                       jti hasn't been revoked
                     → issues a NEW access+refresh pair
                     → OLD refresh token is revoked (rotation)
```

Rotation is the important design choice here: a refresh token can only
ever be used once. If it's used a second time, we know something is
wrong — either the legitimate user's token was already rotated (normal),
or someone is replaying a stolen token after the real user already moved
past it (an attack). We currently just reject the reuse; we don't yet
escalate to "revoke this whole token family" (see "where this is weak,"
below).

### Alternatives we considered

**No refresh tokens at all — just re-login on access token expiry.**
Genuinely the right choice for a lot of apps, especially ones where an
hour-long session is fine (an internal tool, an app people check briefly
and close). We built refresh tokens because we decided — deliberately,
not reflexively — that requiring a password re-entry every hour was a
real UX problem for this project's intended use case (a workspace app
people keep open all day). If your use case doesn't have that problem,
skip this entirely; it's real complexity (a whole extra table, an extra
endpoint, a cleanup job) for a real but specific benefit.

**Sliding-expiration single token** (no separate refresh token; every
successful API call extends the same token's expiry). Simpler — one
token type, no rotation logic. The downside: it makes "log out" and
"force expiry" much harder to reason about, since the token is
continuously extending itself, and it means every single request
(not just the periodic refresh) needs write access to wherever expiry
is tracked, if you want that state persisted rather than purely
client-trusted.

**Refresh token as an opaque random string, not a JWT.** We generate a
`jti` (a UUID) either way and store it — the fact that our refresh token
*also* happens to be a full JWT (with its own signature, subject, and
expiry claim) is somewhat redundant, since we already look it up by
`jti` in the database on every use, which means the database round-trip
is the actual source of truth, not the JWT's own embedded expiry. A
simpler design would make the refresh token just be a random opaque
string (like a session ID), stored directly, with no JWT machinery at
all for this half of the pair. We used a JWT for consistency with the
access token's `JwtService`, but it's fair to call this slightly
over-engineered for what the refresh token actually needs to do.

### Java 17 vs Java 8

The `RefreshToken` entity is a plain JPA `@Entity` — identical
regardless of Java version, since JPA annotations predate both. The one
place worth showing is the claims-extraction code using pattern matching
for `instanceof`, a genuine Java 17 (technically Java 16+) feature:

```java
// Java 17 — pattern matching for instanceof
if (t instanceof SQLException sqlEx) {
    sqlState = sqlEx.getSQLState();
}
```

```java
// Java 8 — the cast is separate and manual
if (t instanceof SQLException) {
    SQLException sqlEx = (SQLException) t;
    sqlState = sqlEx.getSQLState();
}
```

Small difference, but it appears constantly throughout exception-handling
code like ours, so it adds up. Not a security difference — purely
readability — but worth knowing which Java version you need if you're
trying to copy this pattern into an older codebase.

### Where this is weak

- **No token family revocation.** As mentioned, detecting a reused
  (already-rotated) refresh token currently just rejects that one
  request. A more complete implementation would revoke every token
  descended from that same original login (the whole "family"), forcing
  the legitimate user to log in again — treating a reuse as a strong
  signal of compromise. We don't currently have any way to *notify* a
  user this happened (no email infrastructure), which is part of why we
  didn't build the more aggressive response — silently logging someone
  out with no explanation is its own bad experience.
- **No "log out everywhere" endpoint.** There's no way to revoke every
  refresh token for a given user in one action (useful if a user
  suspects their account is compromised, or after a password change).
  Would be a straightforward addition: one query,
  `UPDATE refresh_tokens SET revoked = true WHERE user_id = :id`.
- **No device/session listing.** A user has no way to see "here are the
  3 devices currently logged into my account" or revoke one specifically.
  Real products (GitHub, Google) offer this; it requires tracking a bit
  more metadata per refresh token (device name, IP, last used) than we
  currently store.

---

## 6. The Spring Security filter chain

### The problem

Before a request ever reaches a `@RestController` method, a lot of
cross-cutting concerns need to happen: is this request even allowed
through at all, is there a valid identity attached to it, is that
identity allowed to do what it's asking. Doing this inside every
controller method (`if (!isAuthenticated()) return 401;` at the top of
every method) is repetitive and easy to forget in a new endpoint. Filters
solve this by running *before* routing, uniformly, for every matching
request, whether or not the developer writing a new controller method
remembers to think about security at all.

### What we built, in actual chain order

```
1. RequestSizeLimitFilter   — reject oversized bodies before anything reads them
2. RateLimitFilter          — reject excessive requests to auth endpoints
3. JwtAuthenticationFilter  — populate SecurityContext from a bearer token, if present
4. (Spring's built-in filters: CORS, CSRF (disabled), session management,
   the actual UsernamePasswordAuthenticationFilter our custom ones sit
   "before")
5. AuthorizationFilter      — enforces .hasRole(...) / .authenticated() rules
6. → finally, DispatcherServlet routes to the matching @RestController
```

Every custom filter extends `OncePerRequestFilter`, which is Spring's
own base class guaranteeing the filter runs exactly once per request
even if the servlet container internally forwards/dispatches the request
more than once (this can genuinely happen — error dispatches,
async request handling — and a filter that isn't idempotent-safe could
double-count a rate limit hit or double-validate a token unnecessarily).

Filter *order* is not incidental — we deliberately register
`RequestSizeLimitFilter` before `RateLimitFilter` before
`JwtAuthenticationFilter`, all positioned "before"
`UsernamePasswordAuthenticationFilter` using
`.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)`.
Registering something "before" the same anchor class multiple times
preserves your *registration* order among those — which is why the order
we call `.addFilterBefore(...)` in `SecurityConfig` actually matters and
isn't just a Spring Security implementation detail we got lucky with.

### Alternatives we considered

**Spring MVC interceptors (`HandlerInterceptor`) instead of servlet
filters.** Interceptors run *after* Spring MVC has already done handler
mapping — meaning DispatcherServlet has already decided which controller
method would handle the request. This is meaningfully later in the
pipeline than a filter. For something like our size limit filter, which
needs to reject a request before its body is even read, an interceptor
is architecturally the wrong tool — filters run at the servlet level,
before Spring MVC is even involved. Interceptors are the right tool for
concerns that genuinely need to know *which* controller method is about
to be invoked (e.g., reading a custom annotation on that specific
method) — we don't have that need anywhere in this project.

**Aspect-Oriented Programming (`@Around` advice via Spring AOP)** for
something like rate limiting, applied as an annotation
(`@RateLimited`) on specific controller methods instead of a blanket
filter on specific URL paths. This is a legitimate, more granular
alternative — it would let you rate-limit at the method level with
different limits per endpoint, expressed declaratively. We didn't do
this because our rate limiting only ever needed to apply to two URL
paths, which a simple filter with an `if` check handles with far less
machinery (no proxy creation, no aspect weaving, no separate annotation
to define and document) than introducing Spring AOP into the project
just for this one feature.

### Java 17 vs Java 8

`OncePerRequestFilter` and the whole filter API predate both versions —
zero difference here from the framework's side. The place this shows up
is in how we build small immutable response bodies inline inside a
filter, like the raw JSON string in `RateLimitFilter`:

```java
// Java 17 — text block
response.getWriter().write("""
        {"status":429,"error":"RATE_LIMITED","message":"Too many requests, please try again later"}
        """);
```

We actually wrote this as a single-line string literal in the real code,
but a text block (Java 15+, so also unavailable on Java 8) is the more
natural way to write a multi-line JSON literal without escaping every
quote:

```java
// Java 8 — no text blocks, every quote needs escaping, no multi-line literal
response.getWriter().write(
    "{\"status\":429,\"error\":\"RATE_LIMITED\"," +
    "\"message\":\"Too many requests, please try again later\"}"
);
```

Not a security difference at all — purely about how painful it is to
read and maintain a hand-written JSON literal in the source, which is
part of why we use `ObjectMapper` to serialize our real `ApiError`
objects everywhere else rather than hand-writing JSON strings — this raw
string in the rate limiter is really the *one* place we cut that corner,
specifically because pulling in the injected `ObjectMapper` for a
two-field static message felt like more machinery than the situation
warranted. Worth being honest that this is a minor inconsistency with
the rest of the codebase's own standards.

### Where this is weak

Because we register three custom filters (`RequestSizeLimitFilter`,
`RateLimitFilter`, `JwtAuthenticationFilter`), plus everything Spring
Security itself inserts, a request's actual path through the process
before reaching a controller is now a dozen-plus classes deep — visible
in the stack trace you shared earlier in this project when debugging the
actuator issue. This is normal for Spring Security, but it's genuinely
harder to reason about than a simple single `if` chain, and stack traces
from this layer are intimidating to a newer developer. The mitigation is
exactly this document and the class-level comments in each filter — the
complexity is inherent to the framework, but it doesn't have to be
undocumented.

---

## 7. Authorization — roles vs the alternatives

### The problem

Authentication answers "who are you." Authorization answers "what are
you allowed to do." They're different questions and conflating them is a
common source of real vulnerabilities — an app that only checks "are you
logged in" and never checks "are you allowed to do *this specific
thing*" is an app where any logged-in user can hit any endpoint,
including admin ones, just by knowing the URL.

### What we built

Role-Based Access Control (RBAC), about as simple as RBAC gets: exactly
two roles, `USER` and `ADMIN`, checked at the route level:

```java
.requestMatchers("/api/admin/**").hasRole("ADMIN")
```

The role lives on the `User` entity as a plain string column, gets
turned into a `GrantedAuthority` (`ROLE_ADMIN`) inside
`UserDetailsImpl.getAuthorities()`, and Spring Security's
`hasRole("ADMIN")` matches it (the `ROLE_` prefix convention is handled
for you by `hasRole` — if you use `hasAuthority` instead, you write the
full `"ROLE_ADMIN"` string yourself).

### Alternatives we considered

**Attribute-Based Access Control (ABAC).** Instead of "does this user
have the ADMIN role," ABAC evaluates arbitrary attributes of the user,
the resource, and the context together — e.g. "can this user edit this
document, given their department matches the document's department AND
it's during business hours AND the document isn't locked." Spring
Security supports this via `@PreAuthorize` with SpEL expressions
referencing method arguments, or a full policy engine like OPA (Open
Policy Agent) for genuinely complex rules. We don't need this — every
authorization decision in this app reduces to either a role check or an
ownership check (see section 8), and introducing a general-purpose
policy engine for two decision types would be solving a much bigger
problem than we have.

**Access Control Lists (ACL) — Spring Security ACL module.** Lets you
grant permissions on a *specific object instance* to a *specific user or
role* (e.g., "user 47 can read document 12, specifically, regardless of
their general role"). This is real infrastructure — it needs its own
database tables tracking every individual grant — and it's the right
tool when permissions genuinely vary per-object in ways a simple
ownership check can't express (e.g., a shared document with some editors
and some viewers). Our ownership model (section 8) — "you can touch it
if you created it, full stop" — doesn't need this. If this project grew
a "share this note with another user" feature, ACLs (or a simpler
hand-rolled `note_shares` table) would become the right tool.

**A generic permission-string system** (`"notes:read"`, `"notes:write"`,
`"admin:users:list"`, stored as a many-to-many between users/roles and
permission strings, checked via `hasAuthority("notes:write")`). More
flexible than fixed roles — you can compose fine-grained permissions into
different role bundles without a code change. We don't have anywhere
near enough distinct actions in this app to justify it; two roles and
one admin route is the entire authorization surface. This is exactly the
kind of "looks more enterprise" abstraction the original project brief
told us to avoid building without a concrete need.

### Java 17 vs Java 8

No real difference — `hasRole(String)` is a plain method call on a
builder, string literals are string literals in any Java version. The
`enum` we'd reach for if we had a fixed, closed set of roles known at
compile time is identical in both:

```java
// identical in Java 8 and Java 17
public enum Role {
    USER, ADMIN
}
```

We actually store role as a plain `String` on `User`, not this enum —
worth calling out as a minor inconsistency. Using an enum here would
give us compile-time safety (`Role.ADMIN` can't be typo'd the way a raw
string `"ADIMN"` can) at the cost of needing a JPA `@Enumerated` mapping.
A reasonable improvement if this project grows more roles.

### Where this is weak

Two roles total, and `USER` vs `ADMIN` is a completely flat hierarchy —
there's no "ADMIN implies USER" relationship expressed anywhere; an
admin account also needs the routes that `.anyRequest().authenticated()`
covers to work, which they do, but only because we never scoped a route
as "USER only, explicitly excluding ADMIN." If you ever need a role
hierarchy (e.g., a `MODERATOR` role that's a subset of `ADMIN`'s
powers), Spring Security has `RoleHierarchy` support for exactly this,
unused here because we've never needed more than two flat roles.

---

## 8. Resource ownership vs authorization

### The problem

Role-based authorization answers "can a USER hit this endpoint at all."
It says nothing about *which* note a given USER should be able to fetch
by ID. Without an explicit check, any authenticated user could request
`/api/notes/1`, `/api/notes/2`, `/api/notes/3`... and read everyone's
notes, despite being correctly authenticated and correctly authorized by
role.

### What we built

Every note query is scoped by the authenticated user's own ID, resolved
server-side, never trusted from client input:

```java
private Long currentUserId() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    UserDetailsImpl principal = (UserDetailsImpl) authentication.getPrincipal();
    return principal.getId();
}

@GetMapping("/{id}")
public Note getNote(@PathVariable Long id) {
    return noteRepository.findByIdAndUserId(id, currentUserId())
            .orElseThrow(() -> new ApiException(ErrorCode.RESOURCE_NOT_FOUND, "Note not found: " + id));
}
```

The two ideas that make this actually secure, not just "usually works":

1. **The owner ID never comes from the request.** Not a path parameter,
   not a query parameter, not a request body field. It's derived purely
   from the authenticated token. A request can't claim "I am user 47" —
   the server already knows who it is from the JWT it just validated.
2. **A note that exists but belongs to someone else returns the exact
   same 404 as a note that doesn't exist at all.** This is deliberate.
   Returning `403 Forbidden` for "exists but not yours" would let an
   attacker enumerate valid note IDs by watching for 403 vs 404 — even
   without ever reading the content, that's a real information leak
   (confirms IDs exist, hints at total note count in the system, etc.).

### Alternatives we considered

**A generic "ownable resource" interface/base class** shared across
Notes, Tasks, and Files, with a shared repository method or a base
controller class handling the `currentUserId()` + scoped-lookup pattern
once. We deliberately did *not* build this abstraction, even though it
would reduce repetition once Tasks and Files exist. The reasoning,
stated back when this decision came up: repeating a small, obvious
pattern across a few controllers keeps each one self-contained and
readable in isolation, versus routing every resource's security-critical
lookup through a shared base class where a bug affects every resource
type at once, and where a new reader has to go find and understand the
base class to know what a subclass controller actually does. This is a
judgment call, not a universal rule — a project with ten resource types
instead of two or three would probably tip the balance toward sharing
the pattern.

**Storing ownership as a JPA `@ManyToOne` relationship** instead of a
plain `Long userId` column. We started this way, then deliberately
switched to a plain column with native queries (see the commit history —
this was an explicit mid-project change). The relationship mapping
brings lazy-loading behavior (accessing `note.getOwner().getEmail()`
outside an open Hibernate session throws `LazyInitializationException`)
and hidden join behavior that's easy to get wrong without realizing it,
especially for a project meant to be read by people still learning JPA's
sharper edges. A plain foreign key column with an explicit
`WHERE user_id = :userId` in a native query is more verbose per query,
but what happens is fully visible in the code — nothing is implicit.

### Java 17 vs Java 8

No language-level difference in this pattern at all — it's a private
method and a repository query, both plain since Java 5. Worth noting
regardless: this is the one section where Java version genuinely doesn't
matter even a little, which is itself useful to know — not every good
practice in this codebase is tied to modern syntax; some of it is just
"write the query correctly."

### Where this is weak

`currentUserId()` is duplicated, nearly verbatim, in every resource
controller (see the "alternatives" discussion above for why that's a
deliberate tradeoff, not an oversight). It also does an extra query —
`UserDetailsImpl` already carries the ID from the JWT's claims without
touching the database, so this is genuinely just a method reading a
field, not a fresh lookup; worth stating plainly since "current user"
methods in other frameworks often *do* hit the database unnecessarily,
and ours specifically doesn't.

---

## 9. CORS

### The problem

Browsers enforce the Same-Origin Policy by default: JavaScript running
on `https://frontend.example.com` cannot read the response of a `fetch`
call to `https://backend.example.com`, because the two are different
origins (different domain), unless the *backend* explicitly says it's
okay. This is a browser security feature protecting *users*, not a
feature of our API — without it, any malicious website could silently
make authenticated-looking requests to any API a victim happens to be
logged into elsewhere, using the victim's own browser and (in a
cookie-based world) their own ambient session cookie.

### What we built

An explicit origin allow-list, different per Spring profile, wired into
Spring Security's own CORS support (not just Spring MVC's, which Spring
Security ignores unless told otherwise):

```java
@Bean
@Profile("local")
public CorsConfigurationSource localCorsConfigurationSource() {
    return buildSource(List.of("http://localhost:5173"));
}

@Bean
@Profile("prod")
public CorsConfigurationSource prodCorsConfigurationSource() {
    return buildSource(List.of("https://your-frontend.vercel.app"));
}
```

`allowCredentials(false)` — deliberately, because we're a stateless
bearer-token API, not a cookie-based one. This matters: browsers
categorically refuse to combine a wildcard origin (`*`) with
`allowCredentials(true)` — that combination is specifically disallowed
by the CORS spec, because it would mean "any website can make
authenticated, cookie-carrying requests to this API and read the
response," which is close to the exact attack CORS exists to prevent.
Since we don't use cookies for auth, we don't need `allowCredentials`
at all.

### Alternatives we considered

**A wildcard origin (`*`).** Works, trivially, and is genuinely
tempting during development because it means never debugging a CORS
rejection. The reason not to: it means literally any website on the
internet can call our API from a victim's browser. Combined with a
bearer token, the practical risk is lower than it would be with cookies
(a malicious page can't *read* `localStorage` from another origin to
steal the token in the first place — that's still protected by
same-origin), but a wildcard still means any site's JS can attempt
requests and, if it somehow already has a valid token (e.g. via an XSS
bug on the legitimate frontend), read the response. An explicit
allow-list costs nothing at runtime and removes an entire category of
"we'll tighten it before shipping" technical debt that has a way of
never actually getting tightened.

**Configuring CORS purely in Spring MVC** (a `WebMvcConfigurer` bean with
`addCorsMappings`) instead of through Spring Security. This is a common
mistake, not really a valid alternative: Spring Security's filter chain
runs *before* Spring MVC, so if Security doesn't know about your CORS
config, a preflight `OPTIONS` request can get rejected or mishandled by
the security filters before MVC's CORS handling ever gets a chance to
respond. Hence `.cors(cors -> cors.configurationSource(...))` inside
`SecurityConfig` specifically.

**Environment-variable-driven origins** instead of `@Profile`-gated Java
beans. We actually started this way, then deliberately switched to
hardcoded-per-profile Java (see the earlier discussion in this project's
history) on the reasoning that an allowed origin is a public URL, not a
secret, and profile-based Java code makes the mapping between
environment and origin explicit and visible in one file, versus needing
to check a deployment platform's environment variable configuration to
know what's allowed. Both are legitimate; we simply favor "obvious from
reading the repo" over "configurable without a redeploy" for this
particular value, since it changes rarely.

### Java 17 vs Java 8

Zero difference — `List.of(...)` is a Java 9+ convenience (not even a
"Java 17" feature specifically), and on Java 8 you'd write
`Arrays.asList(...)` or `Collections.singletonList(...)` instead. Not a
security-relevant difference at all, purely a one-word API substitution.

### Where this is weak

The production origin (`https://your-frontend.vercel.app`) is currently
a literal placeholder, not a real deployed URL — a reminder that this
piece of config needs a real, deliberate value before the app is
actually exposed to the internet, not something to leave on
autopilot from a copy-pasted example.

---

## 10. CSRF

### The problem

Cross-Site Request Forgery exploits *ambient* credentials — specifically,
cookies, which browsers attach automatically to any request to a
matching domain, regardless of which page on the internet triggered that
request. Classic example: you're logged into your bank (cookie session),
you visit a malicious page in another tab, that page has an invisible
form auto-submitting a POST to your bank's "transfer money" endpoint —
your browser helpfully attaches your real session cookie, because from
the browser's point of view, it's just a normal request to a domain
you're logged into. The bank's server can't tell the difference between
"the user clicked transfer" and "a malicious page tricked the user's
browser into submitting the same request."

### What we built

```java
.csrf(csrf -> csrf.disable())
```

Disabled, deliberately, for a specific reason stated in the code and
worth restating here: CSRF is fundamentally an attack on *ambient*
credentials. We don't have any. Every request to this API needs an
explicit `Authorization: Bearer <token>` header — and critically, a
malicious third-party page cannot make a victim's browser attach an
arbitrary custom header the way it can make it attach a cookie. The
browser doesn't know or care about our JWT; it's just a string our
frontend's own JavaScript reads from wherever it stored it and adds to
the request manually. A page on `evil.example.com` has no way to read
that value (it's not in a cookie, and even if it were in `localStorage`,
same-origin policy prevents `evil.example.com`'s JS from reading
`legit-frontend.example.com`'s `localStorage`) and therefore no way to
forge a request carrying it.

### Alternatives we considered

**Leaving CSRF protection enabled anyway, "just in case."** Spring
Security's CSRF protection expects a CSRF token to be included in
state-changing requests (POST/PUT/DELETE), generated server-side and
delivered to the client, then echoed back on the next request as proof
the request originated from a page that could actually read that token
(same-origin policy again doing the real work). For a stateless bearer
API, layering this on top of what the bearer token already provides
would be pure friction with no additional protection — the vulnerability
that CSRF tokens defend against structurally doesn't apply to a
credential a malicious page can't get the browser to attach on its own.
We disabled it rather than leaving it on unnecessarily, but the decision
is explicitly written down and dated in a code comment (`SecurityConfig`)
rather than left as an unexplained default, precisely so a future reader
doesn't assume it was an oversight.

**Double-submit cookie pattern.** A CSRF-mitigation technique
specifically for APIs that *do* use cookies for auth but want to avoid
full server-side CSRF token session state. Not relevant to us at all
since we don't use cookies for authentication.

### Java 17 vs Java 8

Not applicable — this is purely a configuration decision (a lambda
disabling a feature), the exact same one line of code regardless of
Java version.

### Where this is weak / when to revisit

If this project ever added a cookie-based authentication mechanism
*alongside* JWT — for example, a first-party web client using an
`HttpOnly` session cookie instead of a JS-held bearer token, which as
discussed in section 3 is a real security upgrade in some ways — CSRF
protection would need to be re-enabled for whatever routes that cookie
protects. This is exactly the kind of decision that must be revisited
if the underlying assumption (no ambient credentials) ever changes; the
code comment says so explicitly for that reason.

---

## 11. Rate limiting

### The problem

Without any limit, an attacker can attempt unlimited password guesses
per second against `/api/auth/login`, or spam-create accounts via
`/api/auth/register`. Every other security control in this project —
hashing, JWT, ownership — is undermined if the front door to obtaining a
valid credential has no friction at all.

### What we built

An in-memory, per-IP token bucket (Bucket4j), applied only to
`/api/auth/login` and `/api/auth/register`, 5 requests per minute per IP,
backed by a bounded, self-evicting cache (Caffeine) rather than an
unbounded map (our first version had a real bug here — an unbounded
`ConcurrentHashMap` that grew forever, fixed in a follow-up commit; worth
reading that commit's message if you want to see the actual bug
demonstrated).

```java
Bandwidth limit = Bandwidth.classic(5, Refill.greedy(5, Duration.ofMinutes(1)));
```

"Token bucket" as a concept: imagine a bucket that holds up to 5 tokens.
Every request consumes one token. The bucket refills at a steady rate
(here, all 5 tokens back after a minute — "greedy" refill means it adds
them all at once rather than trickling one back every 12 seconds; a
"greedy" refill is simpler to reason about, a smoother trickle refill
would allow slightly more consistent request pacing but adds complexity
we didn't judge worth it here).

### Alternatives we considered

**Resilience4j's `RateLimiter` module.** A well-regarded alternative to
Bucket4j, part of a broader resilience toolkit (circuit breakers,
retries, bulkheads) that this project doesn't otherwise need. Bucket4j
is more narrowly focused on exactly the token-bucket algorithm, which
made it the simpler dependency to reach for when we only need one
capability from it.

**Guava's `RateLimiter`.** Older, well-known, but designed primarily for
*smoothing outbound* request rates (e.g., "don't call this downstream
API faster than N times per second"), not for *rejecting inbound*
requests over a limit with a clean HTTP-level response. It's the wrong
shape of tool for this specific job, even though the underlying
algorithm concept (token bucket) is similar.

**A dedicated API gateway** (Kong, Cloudflare rate limiting, AWS API
Gateway's built-in throttling) doing rate limiting *before* traffic ever
reaches the Spring Boot process at all. This is genuinely the more
robust production answer — it defends against volumetric attacks before
they even cost our application any CPU, and a properly configured
gateway can do IP reputation, geographic filtering, and coordinate limits
across multiple backend instances without any of the flaws documented
below. We don't have one in front of this app currently (Render doesn't
provide this by default the way Cloudflare or AWS would), so
application-level rate limiting is what we have, explicitly documented
as a stopgap rather than a complete solution.

### Java 17 vs Java 8

Bucket4j and Caffeine's APIs are identical regardless of Java version —
both are ordinary libraries with builder-pattern APIs, no
version-specific language features involved in using them. The one place
worth showing: the lambda passed to Caffeine's cache-loading method:

```java
// Java 17 — same as Java 8 here, lambdas have existed since Java 8
Bucket bucket = buckets.get(clientIp, ip -> newBucket());
```

Lambdas themselves shipped in Java 8, so this exact line is identical on
both versions — a reminder that "modern Java features" isn't a single
cliff edge at some particular version; lambdas (8), `var` (10), records
(16), pattern matching for `instanceof` (16), text blocks (15), and
sealed classes (17) all landed at different points, and a "Java 8 vs
Java 17" comparison really means "which of these five-ish features would
be unavailable," not one uniform difference.

### Where this is weak

Documented in full, deliberately, directly in `RateLimitFilter.java`'s
class comment and in `docs/adr/002-rate-limiting.md` — repeating the
short version here because it's important enough not to bury: IP address
is a weak identity (shared by everyone behind the same NAT/corporate
network, trivially varied by an attacker with multiple IPs or a botnet),
this is not distributed (each instance has its own bucket map, so
horizontal scaling multiplies the effective limit), and we do not
currently parse `X-Forwarded-For`, which means if this is ever deployed
behind a reverse proxy or load balancer, `getRemoteAddr()` may return the
proxy's IP rather than the real client's — a real risk to verify at
deploy time, not a theoretical one.

---

## 12. Security response headers

### The problem

Browsers respect a set of standard response headers that turn on
specific protective behaviors — but only if the server actually sends
them. Without them, a browser falls back to permissive legacy defaults
that predate these protections existing at all.

### What we built, header by header

**`X-Content-Type-Options: nosniff`** — stops a browser from trying to
"guess" a response's real content type by inspecting its bytes, ignoring
whatever `Content-Type` we actually declared. Matters most for anything
we might ever serve that originated as user input (a future file
upload feature) — without this, a browser might decide bytes we labeled
`image/png` actually "look like" HTML and render them as such, executing
any embedded script.

**`X-Frame-Options: DENY`** — prevents our responses from being rendered
inside an `<iframe>` on another site, defending against clickjacking
(an invisible iframe of a legitimate page laid over a fake UI, tricking
a user into clicking something they didn't intend). `DENY`, not
`SAMEORIGIN`, because this backend never serves a page meant to frame
itself — we're a JSON API, there's no legitimate framing use case at
all.

**`Strict-Transport-Security`** (HSTS) — tells a browser "never attempt
plain HTTP to this host again, for the next year, force HTTPS even if
someone types `http://` or follows an old link." Defends against
SSL-stripping, where a network-level attacker intercepts the *initial*
plaintext request before it would have been upgraded to HTTPS. Only
meaningful once actually served over real HTTPS (which Render provides)
— browsers ignore this header entirely when received over plain HTTP,
so it does nothing on `localhost` during development, which is expected,
not a bug.

**`Referrer-Policy: strict-origin-when-cross-origin`** — controls what
gets sent in the `Referer` header on outbound navigation. This is the
current OWASP-recommended default: full URL on same-origin, origin only
(no path or query string) cross-origin, nothing at all on an HTTPS→HTTP
downgrade. Prevents a URL that happens to contain something sensitive in
its path or query from leaking to a third-party destination via the
Referer header.

**`Cache-Control: no-cache, no-store, must-revalidate`** — actually a
Spring Security default we didn't have to add, kept and documented
rather than overridden. Stops a shared proxy or the browser's own disk
cache from persisting a response that might contain a token or personal
data.

### What we deliberately did NOT set, and why

**`Content-Security-Policy` (CSP)** — arguably the single most powerful
anti-XSS header that exists, and we don't set it. The reason: CSP is a
directive for browsers rendering **HTML documents**, controlling which
script/style/image sources a *page* may load from. This backend never
serves HTML — it serves JSON, consumed by a separately-hosted frontend.
A CSP header on a JSON response does essentially nothing, because
there's no HTML document for a browser to apply the policy to. **CSP
belongs on the frontend** (the Vercel-hosted React/whatever app), not
here — worth stating explicitly so a security review of this backend
doesn't flag its absence as an oversight.

**`X-XSS-Protection`** — a legacy header for a now-entirely-removed
browser feature. Chrome, Firefox, and Edge have all dropped support for
the mechanism this header used to control, and current OWASP guidance
is to explicitly *not* set it — in old, now-rare browsers that still
honored it, this header could itself be turned into an attack vector
(a known technique used it to intentionally *suppress* legitimate
content rather than block malicious content). Better to rely on CSP
(on the frontend) than resurrect a deprecated, sometimes-counterproductive
header here.

### Alternatives we considered

Spring Security's `.headers(...)` DSL is really the only idiomatic way
to do this within the framework; the realistic alternative is setting
these headers manually via a `Filter`, which we already have three of —
we specifically preferred the built-in DSL here because it's the
framework's own blessed mechanism, gets maintained alongside Spring
Security itself, and needs no custom filter-ordering reasoning the way
our other filters do.

### Java 17 vs Java 8

No difference — this is entirely a fluent builder-style configuration
API on `HttpSecurity`, unrelated to Java language version.

### Where this is weak

We're not currently setting `Permissions-Policy` (formerly
`Feature-Policy`), which controls browser feature access (camera,
microphone, geolocation) — not relevant to a JSON API with no camera/mic
usage of its own, but again, this is a frontend concern more than a
backend one, worth confirming is set correctly wherever the actual
HTML-serving frontend lives.

---

## 13. Error handling and information leakage

### The problem

Every error response is potential intelligence for an attacker. "Invalid
password" vs "no such user" tells an attacker which emails are
registered. A stack trace tells them your exact framework versions,
internal class names, and sometimes even fragments of SQL. A generic
"500 Internal Server Error" with no further detail, while frustrating
for legitimate debugging, is exactly what you want an *attacker* to see
— which creates a real tension this project resolves by keeping detailed
information server-side (in logs) and generic information client-side
(in the response).

### What we built

One enum (`ErrorCode`) maps every known failure to an HTTP status, a
machine-readable string, and a default message — see
`ARCHITECTURE.md` for the full reasoning on why this replaced a
per-exception-class approach. The specific information-hiding decisions
worth calling out:

- **Bad password vs. unknown email → identical error.** Both produce the
  generic `BadCredentialsException` → the same response. If these
  differed, an attacker could enumerate valid registered emails by
  watching which response they get back.
- **Someone else's note vs. a nonexistent note → identical 404.**
  Discussed in section 8. Prevents ID enumeration.
- **The generic `Exception` handler never includes `ex.getMessage()`.**
  It logs it (server-side, full detail, full stack trace, at ERROR
  level) but the client only ever sees `"Something went wrong"`. This is
  the single most important line in the whole error-handling system —
  every other handler is specific and safe by construction, but this
  catch-all exists specifically to make sure a bug we didn't anticipate
  can never accidentally leak an internal detail through an unhandled
  exception's default message.
- **`RestAccessDeniedHandler`'s message never names the required role.**
  "You do not have permission to access this resource" — not "you need
  ROLE_ADMIN for this." Naming the missing requirement tells an attacker
  exactly what privilege to go acquire (e.g., via a separate
  vulnerability, or social engineering) to get further.

### Alternatives we considered

**RFC 7807 "Problem Details for HTTP APIs."** A standardized JSON shape
for API errors (`type`, `title`, `status`, `detail`, `instance` fields),
which Spring 6 / Boot 3 actually supports natively via
`ProblemDetail`. We built our own `ApiError` shape instead, predating
when we might have adopted the standard one, mostly because this project
started before deciding to standardize on it and our shape does
everything we need. If starting fresh today, `ProblemDetail` is worth
considering purely for interoperability with tooling that expects the
RFC 7807 shape — functionally, the security properties (what information
gets included or excluded) are a choice you make regardless of which
envelope shape wraps it.

**Different messages per validation failure type**, distinguishing "field
missing" from "field too long" from "field wrong format" with different
error codes each. We collapse all Bean Validation failures into one
`VALIDATION_ERROR` code with a field-specific message. More granularity
here is low-risk (validation errors aren't typically sensitive) and would
be a reasonable enhancement; we kept it simple because nothing in this
project's actual usage needed a frontend to branch logic based on *which
kind* of validation failure occurred, only that one did.

### Java 17 vs Java 8

The `record` we use for `ApiError` is the clearest example of Java 17
convenience showing up in a security-adjacent context — not because
records add any security property, but because a smaller, more obviously
correct class is less likely to accumulate an accidental mutable setter
that some future contributor uses to sneak extra (possibly sensitive)
data onto an already-built error response:

```java
// Java 17
public record ApiError(Instant timestamp, int status, String error, String message, String path) {
    public static ApiError of(ErrorCode code, String path) { /* ... */ }
    public static ApiError of(ErrorCode code, String message, String path) { /* ... */ }
}
```

A record's fields are `final` and there are no generated setters at all
— it's genuinely harder to accidentally mutate an `ApiError` after
construction than it would be with a conventional Java 8 class, where
someone could add a `setMessage(String)` later for convenience and
inadvertently make the object mutable in a way that invites bugs (e.g., a
filter downstream "helpfully" appending debug info to an already-built
error response before it goes out).

### Where this is weak

The `ex.getMessage()` capture for `DataAccessException` (section on
database errors, built a few commits into this project) does walk the
cause chain to extract `SQLState` and the root message for our own logs
— correct and deliberate — but it's worth double-checking, if you extend
this pattern to a new exception type, that you're never accidentally
routing a caught internal message into the *client-facing* `ApiError`
rather than only the server-side log line. This is an easy mistake to
introduce later without noticing, since both code paths look superficially
similar.

---

## 14. Actuator exposure

### The problem

Spring Boot Actuator is extremely useful for operations (health checks,
metrics, live log-level changes) and extremely dangerous if exposed
carelessly — `/actuator/env` can reveal every configuration property
including, depending on setup, imperfectly-masked secrets;
`/actuator/heapdump` produces a full memory snapshot that could contain
live JWT secrets, password hashes mid-verification, or session data;
`/actuator/beans` maps your entire internal object graph, which is a
gift to anyone probing for a way in.

### What we built

Two independent locks, both of which must be separately changed for
anything to leak:

1. **`management.endpoints.web.exposure.include`** decides what exists
   over HTTP at all. In production, only `health`, `info`, `metrics` are
   even registered — everything else genuinely does not exist as an
   endpoint, returning our own 404 `RESOURCE_NOT_FOUND`, not a 401 or
   403 that would at least confirm something is *there* to be denied.
2. **`SecurityConfig`'s `hasRole("ADMIN")` rule** on `/actuator/**`
   (except the explicitly public `/actuator/health/**`) means even
   something on the include-list still needs a valid admin token.

`heapdump` and `shutdown` are never included in either environment's
exposure list, full stop — not even behind the admin check, because the
risk of a heap dump leaking live secrets is severe enough that "requires
an admin token" isn't a comfortable enough bar on its own.

### Alternatives we considered

**A separate management port** (`management.server.port`), which puts
actuator endpoints on an entirely different network port than the main
application — the idea being you'd only expose that port internally
(e.g., to a monitoring system on a private network), never to the public
internet at all. This is genuinely the more robust pattern for a
traditional server deployment. We don't use it here because Render (our
target deployment platform) only routes a single public port per
service, and the platform's own health check needs to reach
`/actuator/health` on that same public port — a separate management port
wouldn't be reachable by Render's health checker at all without
additional platform-specific configuration we don't currently have.

**HTTP Basic Auth specifically for actuator**, separate from our JWT
scheme, is a common pattern in projects that don't otherwise have their
own auth system actuator could piggyback on. We didn't need this since
we already have a working role-based JWT system — reusing
`hasRole("ADMIN")` was simpler than introducing a second, parallel
credential scheme just for operational endpoints.

### Java 17 vs Java 8

Pure configuration-file and Spring Security DSL territory — zero
language-version relevance.

### Where this is weak

`show-details=never` in production means even a legitimate admin
checking `/actuator/health` doesn't see *why* it's down (which component
failed — DB? disk space?) without separately checking `/actuator/metrics`
or the application logs. This is a deliberate safety-over-convenience
tradeoff, correct for what an unauthenticated platform health-checker
should see, but worth knowing you'll need to cross-reference logs for
real incident diagnosis rather than expecting the health endpoint alone
to tell the whole story.

---

## 15. Request size limits

### The problem

Nothing prevents a client from sending an enormous request body. Jackson
will attempt to buffer and parse whatever arrives; a handful of large
concurrent requests can exhaust available memory before any of our own
validation logic even runs, because the problem happens *during*
deserialization, before a `@Valid` annotation gets a chance to reject
anything.

### What we built

A custom filter (`RequestSizeLimitFilter`) because — worth restating,
since it surprises people — **there is no built-in Spring Boot property
that caps a plain JSON request body size on the default embedded Tomcat.**
`spring.servlet.multipart.*` properties only govern multipart/form-data
(file upload) parsing, which is a completely separate code path from
JSON body parsing.

The filter checks two things: a declared `Content-Length` over the limit
gets rejected immediately, before a single byte is read (cheapest
possible rejection). For requests using chunked transfer encoding (no
declared length at all) or a dishonestly small declared length, we wrap
the input stream in a counter that throws once actual bytes read exceed
the limit, mid-parse.

We also added field-level `@Size` constraints (note title capped at 255
to match the database column, content capped at 100,000 characters,
passwords capped at 72 bytes to match BCrypt's own internal truncation
point) so oversized *individual fields* produce a clean 400 from Bean
Validation rather than reaching the database and failing there as an
unhandled 500.

### Alternatives we considered

**Switch to the Undertow embedded server**, which does have a native
`server.undertow.max-http-post-size` property covering exactly this,
with no custom filter needed. A completely valid choice — we stayed on
the default Tomcat because switching embedded servers is a bigger,
less-obviously-justified change than adding one filter class, especially
for a project meant to demonstrate patterns applicable to the far more
common default (Tomcat) setup most Spring Boot tutorials and production
deployments actually use.

**A reverse proxy / CDN-level body size limit** (nginx's
`client_max_body_size`, or equivalent on a platform like Render/Cloudflare)
sitting in front of the application entirely, rejecting oversized
requests before they ever reach the JVM at all — strictly better for
resource protection, since the JVM process never sees the oversized
request. We don't currently have such a proxy configured for this
project's deployment target, so the application-level filter is the only
layer doing this job right now — worth adding a proxy-level limit too, if
one becomes available in your deployment environment, as defense in
depth rather than a replacement.

### Java 17 vs Java 8

The `CountingInputStream` inner class implementing `ServletInputStream`
is ordinary object-oriented code — abstract method overrides, a
constructor, a field. No Java 17 feature makes this meaningfully
different from how you'd write it on Java 8; this is one of the more
"boring," version-agnostic corners of the whole project, worth naming
specifically because it's a useful reminder that not every piece of code
benefits from or needs modern syntax — sometimes a plain class is exactly
the right, unglamorous tool.

### Where this is weak

The 1MB limit is uniform across every JSON endpoint. A future file
metadata endpoint, or any endpoint accepting genuinely large text content,
would need either a higher limit or a path-specific override — the
filter's own comment flags this explicitly as something to revisit when
a file-upload feature is actually built, rather than leaving future
maintainers to discover the ceiling the hard way.

---

## 16. Secrets management

### The problem

A secret committed to git is compromised forever, even if you delete it
in a later commit — git history keeps every prior version, anyone with
clone access (or access to a public repo, ever, even briefly) can find
it by searching history. This is categorically different from a bug you
can just fix going forward.

### What we built

Every genuine secret — `DATABASE_PASSWORD`, `JWT_SECRET` — is read via
Spring's `${VAR_NAME}` placeholder syntax pointing at an OS environment
variable, never given a default value in any committed file. An
unresolved placeholder makes Spring Boot fail at startup with a clear
error naming the missing property — deliberately fail-loud rather than
silently falling back to something insecure or simply broken. Contrast
this with *configuration* that isn't sensitive (CORS origins, rate limit
thresholds, retention durations) which we do commit directly, because
there's no confidentiality requirement and having it visible in the repo
means changes to it show up in `git log` and code review, which is a
genuine benefit for things that aren't secrets.

### Alternatives we considered

**A dedicated secrets manager** (AWS Secrets Manager, HashiCorp Vault,
Google Secret Manager, or Render's own environment variable groups with
sync capabilities). These add real capabilities plain environment
variables don't have: automatic secret rotation, fine-grained access
audit logs (who read this secret and when), and centralized management
across multiple services/environments instead of copy-pasting the same
value into several platforms' dashboards by hand. We use plain
environment variables because this project's scale — one backend
service, no fleet of microservices sharing secrets — doesn't yet justify
the operational overhead of running or subscribing to a separate secrets
management system. This is a very reasonable thing to introduce as a
project grows past a handful of services.

**Spring Cloud Config Server** with encrypted properties, a
Spring-ecosystem-native way to centralize configuration (including
encrypted secrets) across multiple services. Similar reasoning to
above — real value at multi-service scale, unnecessary overhead for one
service.

**`.env` files loaded via a library like `dotenv-java`.** Convenient for
local development (one file instead of manually exporting several
variables every session), genuinely risky as a habit — a `.env` file
sitting in a project directory is one accidental `git add .` away from
being committed, and "just remember to gitignore it" has a well-documented
track record of eventually failing for *someone* on *some* team. We
chose to document environment variables clearly (see
`docs/CONFIGURATION.md`) and rely on IDE run-configuration environment
variables or shell exports instead, specifically to avoid ever having a
file that *looks like* it should be committed sitting in the project
directory at all.

### Java 17 vs Java 8

Not language-relevant — `${VAR_NAME}` placeholder resolution is a Spring
Framework property-source feature, unrelated to the Java language
version running underneath it.

### Where this is weak

No secret rotation mechanism exists for either the database password or
the JWT secret — rotating either today means manually updating the
environment variable and restarting the process, and for the JWT secret
specifically (see section 4's "where this is weak"), rotating it
invalidates every currently-valid token still in circulation, an
operational event with no graceful transition path currently built.

---

## 17. Logging as a security control

### The problem

The client-facing response is deliberately generic for nearly every
failure (section 13). Without a complementary server-side record, that
same principle — hiding detail from the client — would also mean hiding
it from *us*, leaving no way to actually investigate what happened when
something goes wrong or someone attempts to attack the system.

### What we built

Every failure path logs independently of, and in addition to, whatever
the client receives, with severity matched to actual significance:

- **`ERROR`** — reserved for genuinely unexpected exceptions (the
  generic `Exception` catch-all, database exceptions). These get the
  full exception object passed to the logger (not just
  `ex.getMessage()`), which SLF4J renders as a complete stack trace
  including the full cause chain — this is exactly the detail we refuse
  to send to a client, kept for ourselves.
- **`WARN`** — expected-but-notable failures: authentication failures,
  access-denied events, rate-limit rejections, account-related security
  events. Not bugs in our code, but events worth being able to search
  for and count.
- **`INFO`** — routine, low-signal events: validation failures, 404s
  from genuinely unknown routes. Recorded, but deliberately not noisy
  enough to bury real problems when scanning logs.

### Alternatives we considered

**Logging failures directly into a database table**, enabling SQL
queries like "show every failed login for this user in the last month."
Deliberately not built. The reasoning, worth restating because it's a
real anti-pattern worth naming: writing to the *same* database that's
already under load, from *inside* the same request path that's already
failing, means a database problem can now cause your error-handling
code to itself throw a new error, potentially masking or corrupting the
original failure you were trying to record. If a persisted, queryable
audit trail becomes a genuine requirement, the correct shape is an
async, best-effort write (a message queue, a separate write-behind
process) — never synchronous, inline, in the exception-handling path
itself.

**Structured JSON logging** (each log line emitted as a JSON object with
named fields, rather than a formatted string) instead of SLF4J's default
human-readable format. Genuinely the better choice for feeding logs into
an aggregation system like Datadog, Elasticsearch, or Grafana Loki, since
those tools can index and query structured fields far more efficiently
than parsing formatted text. We use SLF4J's parameterized logging
(`log.warn("... ip={} path={}", clientIp, path)`) which is *structured
enough* to grep or basic-filter reliably, without adding a JSON logging
library dependency this project's current scale doesn't yet need. Worth
upgrading if/when real log aggregation tooling enters the picture.

### Java 17 vs Java 8

SLF4J's API (`Logger`, `LoggerFactory`, parameterized `{}` placeholders)
predates both Java versions entirely — no relevant difference. The one
place Java 17 helps readability, not security: our multi-branch
cause-chain walking logic reads more clearly with pattern-matching
`instanceof`, shown already in section 5's comparison.

### Where this is weak

Nothing is currently correlating a single request's log lines together
with a request ID (a common pattern: generate a UUID per incoming
request, put it in the SLF4J MDC, have every log line for that request
automatically include it). Right now, tracing "everything that happened
during this one problematic request" across multiple log lines from
different filters/handlers requires manually correlating by timestamp
and other clues, rather than filtering by one ID. A reasonable near-term
improvement.

---

## 18. Java 17 language features used, and their Java 8 equivalents

A consolidated reference, gathering every place this project actually
leans on a post-Java-8 feature, since the sections above scatter these
throughout their specific security context.

### Records (Java 16+)

Used for: `ApiError`, `LoginResponse`, `RegisterRequest`, `LoginRequest`,
`RefreshRequest`, `CreateNoteRequest`, `IssuedToken`. Every one of these
is a pure data carrier — construct it, read its fields, never mutate it.
This is exactly the case records exist for. On Java 8, each becomes a
full hand-written class: private final fields, a constructor, accessor
methods (record accessors are `name()`, not `getName()` — a real,
if minor, migration wrinkle if you ever port this back), plus
`equals`/`hashCode`/`toString` if you want value semantics rather than
identity semantics (records generate all three automatically; Java 8
classes need them hand-written or generated by your IDE).

### Pattern matching for `instanceof` (Java 16+)

Used in: the `DataAccessException` cause-chain walk, the
`RestControllerAdvice`'s type-checking logic in a couple of handlers.
Collapses a cast-after-check into one expression. Purely readability —
no functional or security difference from the Java 8 two-step version.

### `var` (Java 10+)

Used sparingly, e.g. `var authentication = new UsernamePasswordAuthenticationToken(...)`
in `JwtAuthenticationFilter`. Purely local-variable type inference — the
compiled bytecode is identical to writing the full type explicitly.
Zero functional difference from Java 8, which requires spelling out
`UsernamePasswordAuthenticationToken authentication = ...` in full.

### Text blocks (Java 15+)

Used in a couple of native `@Query` annotations (the multi-line SQL for
`deleteExpiredBatch`) and could be used for the raw JSON literal in
`RateLimitFilter` (currently written as a single-line string instead —
noted as a minor inconsistency in section 6). On Java 8, any multi-line
string needs explicit `\n` and string concatenation across lines, which
gets genuinely hard to read for a multi-line SQL statement.

### Enhanced switch expressions (Java 14+)

Not currently used anywhere in this project — worth noting as an
absence, not a presence. `TokenType` and `ErrorCode` are both handled via
`enum` methods and `if`/`equals` checks rather than switch expressions.
A reasonable modernization if this project's control flow around those
enums grows more complex.

### Sealed classes/interfaces (Java 17)

Not used anywhere in this project. Would be a reasonable fit if
`ErrorCode` or a similar closed-set concept ever needed to become a
richer type hierarchy (e.g., different subclasses per error category
carrying different extra data) rather than a flat enum — sealed types let
you express "these are the only possible subtypes" with compiler-enforced
exhaustiveness in a `switch`. Nothing in this project currently needs
that level of structure.

### What this all means practically

None of the above changes what this application actually *does* from a
security standpoint. Every feature in this list is a readability and
boilerplate-reduction improvement, not a new capability. If you're
maintaining a Java 8 codebase and reading this document for security
guidance rather than syntax modernization, every architectural decision
in sections 1 through 17 applies identically — you'll just be writing
more lines per class to express the same ideas.

---

## 19. Decision summary table

| Concern | We chose | Main alternative | Why not the alternative (short version) |
|---|---|---|---|
| Password hashing | BCrypt | Argon2 | BCrypt is the more battle-tested Spring default; Argon2 is arguably stronger and worth it for a new project with no legacy constraint |
| Session vs token | Stateless JWT | Sessions + Spring Session/Redis | Anticipated multi-origin, multi-instance deployment; sessions + Redis is a legitimate, arguably better choice for a same-origin app |
| JWT signing | Symmetric HMAC (HS256) | Asymmetric RSA/EC | Only one process issues and verifies tokens; asymmetric matters once multiple services need to verify without the power to issue |
| JWT library | jjwt | Nimbus JOSE+JWT | jjwt's fluent API is more approachable for a learning-focused project; Nimbus is the better fit for full JOSE/encrypted-token needs |
| Refresh strategy | Rotating refresh tokens | No refresh tokens (re-login on expiry) | This project's use case (all-day sessions) justified the added complexity; many apps genuinely don't need this |
| Authorization model | Flat RBAC (2 roles) | ABAC / ACL / permission strings | Only two roles and one admin route exist; more general models solve problems this app doesn't have |
| Rate limiting | In-memory per-IP (Bucket4j) | Redis-backed distributed limiter / API gateway | Single instance, no adversarial traffic yet; documented as a stopgap, not a complete defense |
| CSRF | Disabled | Enabled with token echoing | No ambient credentials (no cookies) for CSRF to exploit in the first place |
| Actuator exposure | Allow-list + role check, two independent locks | Separate management port | Render routes one public port; platform health checks need the same port the app serves |
| Schema management | Manual SQL per commit | Flyway / Liquibase | Deliberate choice for this project's teaching goals; **recommended to switch to a migration tool for any real team project** |
| Secrets | Plain OS environment variables | Vault / cloud secrets manager | Single-service scale doesn't yet justify the operational overhead |
| Logging | SLF4J to stdout | Database-backed audit log | Avoids coupling error handling to a database that might itself be the thing failing |

---

## Closing note

Every "where this is weak" section above is there on purpose. A security
document that only explains what's good and never what's missing isn't
actually useful to whoever reads this repo next — including a future
version of whoever wrote it. If you're using this project as a base for
something real: read the weak points relevant to your use case before
you ship, not after.