# Security, explained like I'd explain it to a teammate

This is the long version of every security decision in this backend. The
commit messages tell you *what* changed. This tells you *why*, what else
I looked at, what it would look like on an older JDK, and where I know it's
still weak.

I wrote it for two kinds of reader. If you're using this repo as a starting
point for your own project, read the "what else we could have done" parts
first, because they're where you decide whether to keep my choice or swap it.
If you're reviewing the code, read the "where it's still weak" parts. I'd
rather you hear about the holes from me.

> **How to read this:** every section has the same five beats. *Why it matters*,
> *what we built*, *what else we could have done*, *Java 17 vs Java 8*, and
> *where it's still weak*. Skip around freely. Nothing depends on reading in order.

> **A word on honesty:** a few things in this repo are deliberately unfinished.
> They're marked **Known gap** and collected at the end. Nothing here is
> hidden, and none of it is "we'll fix it later" without saying so.

---

## Contents

1. Password storage
2. The authentication call chain
3. Sessions vs JWT
4. Inside a JWT
5. Access and refresh tokens
6. The filter chain
7. Authorization and roles
8. Resource ownership
9. CORS
10. CSRF
11. Rate limiting
12. Security response headers
13. Error handling and what we refuse to say
14. Actuator
15. Request size limits
16. Secrets
17. Logging as a security tool
18. Java 17 features used here
19. Decision table
20. Known gaps

---

## 1. Password storage

### Why it matters

Sooner or later somebody's database leaks. Maybe it's yours, maybe it's a
backup that ended up in the wrong bucket, maybe it's a SQL injection in code
you didn't write. You can't promise it won't happen. What you can control is
what the attacker is holding when it does.

If passwords are stored in plain text, they're holding everyone's password,
and people reuse passwords, so they're holding keys to a hundred other sites
too. If passwords are hashed properly, they're holding a pile of puzzles that
cost real money to solve one at a time. Same breach, very different day.

### What we built

BCrypt, through Spring's `BCryptPasswordEncoder`:

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

The stored value looks like this:

```
$2a$10$N9qo8uLOickgx2ZMRZoMye1J8O9pjLIcHkTIgtSJhYYKGxTKS0hqi
```

That string is packed with information. `$2a$` is the algorithm version.
`10` is the cost factor, meaning 2^10 rounds of work. The next 22 characters
are the salt, and the rest is the hash itself. Because the salt travels inside
the string, there's no separate `salt` column to keep in sync, and no way to
lose it.

Two properties make BCrypt right for passwords and SHA-256 wrong for them:

**It salts for you.** Every call to `encode()` generates a fresh random salt.
Two users who both picked `hunter2` get completely different hashes. Without
salts, an attacker precomputes one giant table of hash-to-password pairs and
cracks every row of every database at once.

**It's slow on purpose.** SHA-256 is built to be fast, which is lovely for
checksumming a file and terrible for passwords. A GPU can try billions of
SHA-256 guesses a second. BCrypt makes each guess cost a few milliseconds, so
billions per second becomes thousands. That's the entire trick: you can't make
guessing impossible, but you can make it expensive enough to not be worth it.

There's a side effect you'll feel in development: a login takes noticeable
time, and a `matches()` call is the heaviest thing in the request. That's the
slowness working as designed. It's also why we cap password length at 72 bytes
(more on that in section 15) and why rate limiting login matters (section 11):
each attempt costs the server real CPU.

### What else we could have done

**PBKDF2** (`Pbkdf2PasswordEncoder`). This is the one to pick if you need FIPS
or NIST compliance, because BCrypt isn't on those lists. The tradeoff is that
PBKDF2's slowness is only repeated hashing, which parallelizes well on GPUs
and custom hardware. If nobody's forcing compliance on you, there are better
options.

**Argon2** (`Argon2PasswordEncoder`, needs BouncyCastle). The winner of the 2015
Password Hashing Competition and honestly the strongest default today. It
lets you tune memory cost as well as CPU cost, and memory is exactly what GPUs
and ASICs are short on per core. If I were starting a brand new project with
no history to respect, I'd seriously consider it. I stayed with BCrypt because
it's built into `spring-security-crypto` with zero extra dependencies, it's what
most Spring teams already know, and for this app's threat model the gap
between the two isn't the thing that'll hurt us.

**SCrypt.** Same memory-hard idea as Argon2, but older and generally
considered superseded by it. Not wrong, just not the current best answer.

**Rolling your own** (salt plus SHA-256 plus a loop). Please don't. The concept
isn't wrong, the details are. Cost tuning and resistance to custom hardware are
easy to get subtly wrong, and there's no upside when audited code is one
dependency away.

### Java 17 vs Java 8

The encoder wiring is identical on both. `BCryptPasswordEncoder` has looked
the same since Spring Security 4. The only thing the JDK changes is the
boilerplate around it. If you wanted a tiny value object for a check result,
Java 17 gives you:

```java
public record PasswordCheckResult(boolean matches, boolean needsRehash) {}
```

and Java 8 gives you this:

```java
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
    public int hashCode() { return Objects.hash(matches, needsRehash); }

    @Override
    public String toString() {
        return "PasswordCheckResult{matches=" + matches + ", needsRehash=" + needsRehash + '}';
    }
}
```

Nothing about *security* changed. You just have to read twenty lines to find
the two that matter. That's the pattern you'll see in every Java 8 comparison
in this document.

### Where it's still weak

The cost factor is whatever Spring's default is (10 right now), and hardware
only gets faster. A cost that's painful today is cheap in five years.
Spring has `DelegatingPasswordEncoder` for exactly this: it prefixes each hash
with its algorithm (`{bcrypt}$2a$...`), so you can switch encoders later and
still verify old hashes, then quietly re-hash on next login. We inject
`BCryptPasswordEncoder` directly instead, so we don't get that upgrade path
for free. If this project lives long, that's worth changing.

---

## 2. The authentication call chain

### Why it matters

"Check whether the password is right" sounds like one `if` statement, and for
a single login method it basically is. The reason Spring Security looks like
overkill is that it's built so the *same* pipeline can handle passwords, LDAP,
OAuth, SSO headers and whatever else, without your controller knowing which one
is in play. You pay for that flexibility up front, even if you only ever use one.

### What we built

When `/api/auth/login` runs, this is what actually happens:

```
AuthenticationManager.authenticate(token)
        ↓
ProviderManager              (the real class behind the interface)
        ↓
DaoAuthenticationProvider    (ours, registered as a bean)
        ↓
UserDetailsServiceImpl.loadUserByUsername(email)
        ↓
UserRepository.findByEmail(email)
        ↓
PasswordEncoder.matches(rawPassword, storedHash)
```

Each box has one job, and it helps to say it in plain words:

- **`AuthenticationManager`** is the front desk. Your code hands it credentials
  and gets back either a verified identity or an exception. It doesn't know or
  care how the checking happens.
- **`ProviderManager`** is what you actually get when you ask for an
  `AuthenticationManager` bean. It keeps a list of providers and tries each one
  until somebody succeeds. We register exactly one, but you could add an LDAP
  provider next to it and logins would try both.
- **`DaoAuthenticationProvider`** knows one recipe: look the user up through a
  `UserDetailsService`, then compare passwords with a `PasswordEncoder`. "Dao"
  just means it talks to a data source.
- **`UserDetailsService`** is the seam between Spring Security's world and our
  `User` entity. One method. It says "username", but it just means "whatever
  uniquely identifies a user", which for us is an email.

One subtle behavior worth knowing, because it'll confuse you while debugging:
if the email doesn't exist, `DaoAuthenticationProvider` internally throws
`UsernameNotFoundException`, then converts it into `BadCredentialsException`
before it reaches you. That's on by default (`hideUserNotFoundExceptions`) and
it's deliberate. An attacker should get the same failure for "no such user" and
"wrong password". You'll never see the user-not-found case surface at the
controller, and that's the feature working.

### What else we could have done

**Skip all of it and check by hand in the controller:**

```java
User user = userRepository.findByEmail(email).orElseThrow(...);
if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
    throw new BadCredentialsException("bad password");
}
```

This genuinely works, and for a tiny app with one login method and no plans for
a second, it's a defensible choice. We didn't, for two reasons. Going through
`AuthenticationManager` hands you a properly built `Authentication` with
authorities attached, and doing that by hand is how you forget the authorities
and wonder why a role check fails later. And this repo is meant to show what a
real setup looks like, so someone can add LDAP or SSO later along the grain of
the framework instead of fighting it.

**One custom provider that does lookup and check in a single class.** Also
fine. We kept `UserDetailsService` separate because other code wants it too:
the JWT filter loads users through it. Merge it into a provider and either
that filter depends on a class never meant to be called directly, or the lookup
logic gets copy-pasted.

### Java 17 vs Java 8

Nothing changes in the provider or service classes. They implement interfaces
and are plain classes either way.

`UserDetailsImpl` is where people expect Java 17 to help and it doesn't. It
implements `UserDetails`, which has methods like `isAccountNonExpired()` that
we all answer with `return true;`:

```java
@Override public boolean isAccountNonExpired()     { return true; }
@Override public boolean isAccountNonLocked()      { return true; }
@Override public boolean isCredentialsNonExpired() { return true; }
@Override public boolean isEnabled()               { return true; }
```

Same on Java 8. A `record` can implement an interface, but it still has to
spell out every interface method, so there's nothing to save. It's worth
knowing that "newer Java" doesn't always mean "less code".

### Where it's still weak

We only register one provider, and `isAccountNonLocked()` always returns `true`.
That's honest today because we have no lockout feature, but the hook is there
if you add one: return `false` from that method and Spring will refuse the login
for you, with the right exception type.

---

## 3. Sessions vs JWT

### Why it matters

HTTP forgets you between requests. You prove who you are on request 1, and
request 2 shows up with no memory of that. Everything in this section is about
what carries your identity forward. There are really only two families of
answer: the server remembers you (sessions), or you carry proof with every
request (tokens).

### What we built, and why in that order

I built sessions first on purpose. Not because they were a mistake, but
because it's the clearest way to see what JWT trades away. (The short decision
record is in `docs/adr/001-session-vs-jwt.md`. This is the long version.)

**Sessions:**

```
login   → server stores your Authentication in a session,
          sends you a random session ID in a cookie
request → browser attaches the cookie by itself
        → server looks the ID up, finds your Authentication, carries on
```

The server is doing real work: holding state for every logged-in user for as
long as the session lives. The browser does almost nothing, because cookie
handling is automatic. That automatic part is a security win in one way (see
HttpOnly below) and a security risk in another (see CSRF, section 10).

**JWT:**

```
login   → server verifies credentials, builds a signed token, returns it as a string
request → the CLIENT attaches it, usually in an Authorization header
        → server verifies the signature and expiry. No lookup, no state.
```

Verifying a JWT is pure computation: check a signature, check a clock. No
database call, no shared session store, nothing remembered. That's what
"stateless" means here, and it's the whole reason JWT plays nicely when you
run several backend instances behind a load balancer. Any instance can verify
any token, because verification doesn't depend on which one issued it.

### What else we could have done

**Sticky sessions.** Configure the load balancer to always send you to the same
instance. Real teams do this. The catch is that you've welded your
infrastructure to a routing rule, and if that instance dies, everyone stuck
to it is logged out. It also doesn't fix the cross-origin cookie headaches of a
separate frontend and backend, which is what actually decided it for us.

**Spring Session with Redis.** Keep the session model, but store sessions in a
shared Redis so every instance can read them. This really does solve
multi-instance scaling *and* keeps `HttpOnly` cookies. Honestly, for a
same-origin app this is often the better answer than JWT, and I'd want you to
evaluate it before reaching for JWT by default. We didn't build it because it
adds Redis to the stack and one goal here was demonstrating JWT.

**Opaque tokens.** A random string, stored server-side, sent as a bearer token.
You get "attach it manually, no cookie friction" like JWT, and "server can
kill it instantly" like a session. The price is a lookup on every request,
so you've given up statelessness. Some systems use short-lived opaque access
tokens specifically for the instant revocation. It's a real middle path.

### What we gave up by choosing JWT

I want to be straight about this, because tutorials tend to skip it.

1. **No instant revocation.** Once issued, a JWT is good until it expires. The
   server can't reach out and cancel it. Our mitigation is a short lifetime
   (1 hour). Refresh tokens (section 5) are stateful on purpose, so *they* can be
   revoked. That's a quiet admission that pure statelessness isn't what we
   actually want everywhere.

2. **No `HttpOnly`.** A cookie can be marked so JavaScript can't read it, which
   means even an injected script can't steal it. A JWT held in `localStorage`
   or a variable is readable by any script on the page. So we've shifted risk
   onto "don't have an XSS hole in the frontend", which is a heavier thing to
   promise than it sounds.

3. **Bigger requests.** A session cookie is a ~32-byte ID. Our JWT is a few
   hundred bytes on every request. Irrelevant at our scale, just not free.

### Java 17 vs Java 8

`SessionCreationPolicy.STATELESS` is an enum constant. Identical everywhere.
The only comparison worth making is cultural: keeping an ADR in the repo,
versioned next to the code it justifies, is a habit that spread during the same
years Java was modernizing. You can do it on Java 8 just fine. It's a
convention, not a `pom.xml` line.

### Where it's still weak

We picked JWT because of the deployment we *expect* (separate frontend origin,
maybe several instances), not one we measured. If this stayed a single instance
with a same-origin frontend, sessions would have been simpler and arguably
safer by default. If those assumptions change, re-open this decision.

---

## 4. Inside a JWT

### Why it matters

Once you hand the client a token instead of a cookie, you need a format they
can carry as an opaque string, and a way for any instance to verify it wasn't
forged or edited without calling a database.

### What we built

A JWT is three base64url chunks joined by dots: `header.payload.signature`.
Paste any JWT into jwt.io and you'll read the first two in plain text.

> **Heads up:** a JWT is *signed*, not *encrypted*. Anyone who gets hold of it
> can read every claim. The secret only proves nobody *changed* it. Never put a
> password, a card number or anything private in the claims.

Ours decodes to:

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

What each claim is doing for us:

- **`sub`**: who the token is about. We use the email, since that's our unique
  identifier and the same thing `UserDetailsServiceImpl` looks up.
- **`iss`**: who minted it. With one backend this feels pointless, but we
  enforce it on validation (`requireIssuer`), which costs nothing and means a
  validly-signed token from some other system sharing a secret won't pass.
- **`jti`**: a unique ID for *this* token. It looks like decoration until you
  need to revoke one specific refresh token. You can't un-issue a JWT, but you
  can mark its `jti` revoked in your own table and check it.
- **`type`**: ours, not standard. It says ACCESS or REFRESH, so one can never
  be passed off as the other.
- **`iat` / `exp`**: issued-at and expiry, as Unix seconds.

Signing is two lines:

```java
this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
// ...
Jwts.builder().subject(email) /* ... */ .signWith(signingKey).compact();
```

`hmacShaKeyFor` builds a symmetric key: the same secret signs and verifies.
jjwt picks the algorithm from the key length, so 32+ bytes gives HS256, 48+
gives HS384, and 64+ gives HS512.

> **Practical gotcha:** jjwt 0.12 refuses keys shorter than 256 bits and throws
> `WeakKeyException` at startup. If your app dies on boot after you set a short
> `JWT_SECRET`, that's why. Use `openssl rand -base64 32` and move on.

### What else we could have done

**Asymmetric signing (RS256, ES256).** A private key signs and a public key
verifies, and you can hand the public key to anyone. That matters when several
services need to *check* tokens but only one should be able to *issue* them.
We have one process that does both, so symmetric is simpler and faster. If this
ever splits into services, this is the first thing to revisit.

**Nimbus JOSE + JWT** instead of jjwt. Nimbus is more complete (it does full
JOSE, including encrypted JWE tokens) and it's what Spring's own OAuth2
resource server uses underneath. jjwt has a friendlier fluent API, which is why
I picked it for a repo people are supposed to read. If you ever need encrypted
tokens, move to Nimbus.

**Auth0's `java-jwt`.** Similar spirit to jjwt. No strong reason to prefer one.

**PASETO.** A newer format designed to remove JWT's footguns, most famously the
`alg: none` attack, where sloppy verifiers trusted the algorithm named *inside*
the token and accepted unsigned ones. We're not exposed to that, because we
always supply and enforce the verification key ourselves instead of trusting
whatever the token claims. PASETO removes the whole bug class by design, but JWT
has far better tooling and support, so we stayed.

### Java 17 vs Java 8

Here's the real code:

```java
// Java 17, jjwt 0.12 fluent API
return Jwts.builder()
        .subject(subjectEmail)
        .issuer(ISSUER)
        .id(jti)
        .claim(CLAIM_TOKEN_TYPE, type.name())
        .issuedAt(now)
        .expiration(expiry)
        .signWith(signingKey)
        .compact();
```

And what you'd see in a typical Java 8-era project, which means jjwt 0.9.x:

```java
return Jwts.builder()
        .setSubject(subjectEmail)
        .setIssuer(ISSUER)
        .setId(jti)
        .claim(CLAIM_TOKEN_TYPE, type)
        .setIssuedAt(now)
        .setExpiration(expiry)
        .signWith(SignatureAlgorithm.HS256, secretKeyBytes)
        .compact();
```

Spot the difference: `setSubject` vs `subject`, and the algorithm named as a
separate argument. That isn't a Java change, it's jjwt's API evolving. It's also
exactly the bug we hit earlier in this project: the `.subject()` code pasted
against a 0.11.5 dependency, where the method doesn't exist yet. Copying code
between tutorials written years apart is the usual way to get bitten.

The language-level difference is the small `IssuedToken` carrier:

```java
public record IssuedToken(String token, Instant expiresAt) {}   // Java 17
```

On Java 8 that's a final class with two fields, a constructor, two accessors and
the usual `equals`/`hashCode`/`toString`. And note that `java.time.Instant` is
Java 8 already, so our time handling reads the same on both. The `Date` objects
you see around jjwt are there because jjwt's API wants `java.util.Date`, not
because of a JDK limit.

### Where it's still weak

One static secret, loaded once, valid forever. There's no key rotation. If the
secret leaks, every token ever issued is forgeable until natural expiry, and
rotating the secret logs everyone out at once. Mature setups put a `kid` (key
ID) in the JWT header and accept several keys at the same time, so you can
introduce a new one, let old tokens age out, and retire the old key without a
flag day. We didn't build that. It's more machinery than this project's current
scope earns, but you should know the gap exists.

---

## 5. Access and refresh tokens

### Why it matters

Short-lived tokens are safer, since a stolen one dies quickly, but they're
annoying: users get kicked out constantly. Long-lived tokens are comfortable
and dangerous. The usual way out is to use both: a short-lived access token
for real API calls, and a long-lived refresh token whose only job is "trade me
for a new access token". It shows up rarely, and it can be revoked.

### What we built

```
login          → access token (1 hour) + refresh token (14 days, stored by jti)
access expires → client POSTs the refresh token to /api/auth/refresh
               → server checks it's REFRESH-type and its jti isn't revoked
               → issues a NEW pair, revokes the OLD refresh token (rotation)
```

Rotation is the interesting part. A refresh token works exactly once. If it's
ever presented a second time, something's off: either it's an honest retry
after a network glitch, or someone is replaying a stolen token after the real
user already moved past it. Today we just reject the second use.

The refresh token is also persisted, but only by `jti`. We never store the
token itself, because the signature already proves it's genuine. The table's
only job is answering "has this specific ID been used or revoked?"

### What else we could have done

**No refresh tokens at all.** Re-login when the access token expires. This is
the right call for a lot of apps, especially internal tools that people open
briefly. We built refresh tokens because I decided, on purpose, that typing a
password every hour was a real UX problem for an app people keep open all day.
If you don't have that problem, skip all of this: it's a table, an endpoint
and a cleanup job for a specific benefit.

**One sliding token.** Every request extends the same token's expiry. Fewer
moving parts, but "log out" and "force expiry" become very hard to reason
about, and if you persist the expiry, every request becomes a write.

**An opaque refresh token instead of a JWT.** Honestly, our refresh token being
a full JWT is slightly redundant. We look it up by `jti` in the database on
every use anyway, so the database is the real source of truth, not the
embedded expiry. A random string would do the job. I used a JWT for symmetry
with the access token and to reuse `JwtService`, but it's fair to call that a bit
over-engineered.

### Java 17 vs Java 8

The `RefreshToken` entity is a plain JPA class, identical on both. The place
the JDK shows up is exception handling, where we walk cause chains:

```java
// Java 17, pattern matching for instanceof
if (t instanceof SQLException sqlEx) {
    sqlState = sqlEx.getSQLState();
}
```

```java
// Java 8, test then cast
if (t instanceof SQLException) {
    SQLException sqlEx = (SQLException) t;
    sqlState = sqlEx.getSQLState();
}
```

A readability win, nothing more, but it appears all over error-handling code,
so it adds up.

### Where it's still weak

- **No token-family revocation.** On detecting reuse we reject that one request.
  A stricter design would revoke *every* token descended from that login and
  force a fresh password. We didn't, partly because we can't tell the user it
  happened (no email infrastructure), and silently logging someone out with no
  explanation is its own bad experience.
- **No "log out everywhere".** One query would do it
  (`UPDATE refresh_tokens SET revoked = true WHERE user_id = :id`). Worth adding
  after password changes.
- **No device list.** Real products show "you're signed in on 3 devices". That
  needs extra metadata per refresh token that we don't store.

---

## 6. The filter chain

### Why it matters

Before a request reaches your `@RestController`, a lot has to happen: is it
even allowed through, is there an identity attached, is that identity allowed
to do this. You *could* put `if (!loggedIn) return 401;` at the top of every
controller method. You'd also eventually forget it in one, and that one is the
endpoint that gets found. Filters fix this by running before routing, for every
matching request, whether or not the person writing the next endpoint
remembers security exists.

### What we built

This is the order a request walks through. It's deliberate:

```
1. RequestSizeLimitFilter    reject oversized bodies before anything reads them
2. RateLimitFilter           throttle login/register
3. JwtAuthenticationFilter   if there's a valid bearer token, fill the SecurityContext
4. Spring's own filters      CORS, headers, session handling, and so on
5. AuthorizationFilter       enforce .hasRole(...) and .authenticated()
6. DispatcherServlet         finally route to your controller
```

The cheap, dumb rejections come first. There's no reason to parse a JWT for a
request we're going to throw out for being 500MB. Each of our three filters
extends `OncePerRequestFilter`, which guarantees it runs once per request even
if the container re-dispatches internally (error dispatches and async handling
can do that), so we never double-count a rate limit hit.

How the ordering is actually expressed:

```java
.addFilterBefore(requestSizeLimitFilter, UsernamePasswordAuthenticationFilter.class)
.addFilterBefore(rateLimitFilter,        UsernamePasswordAuthenticationFilter.class)
.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
```

All three are anchored "before" the same built-in filter. When you do that,
Spring Security keeps them in registration order, so the order you write these
lines in matters. It isn't a lucky implementation detail. (Your actual stack
trace from the actuator debugging session shows it: `RateLimitFilter` ahead of
`JwtAuthenticationFilter`.)

The JWT filter has one important manners rule: **it never rejects a request
itself.** If the header is missing or the token is bad, it simply doesn't fill the
`SecurityContext`, and the request carries on unauthenticated. Rejection is the
job of the authorization rules and our `AuthenticationEntryPoint` further down.
That keeps one path for "you're not authenticated" instead of two, so a bad
token and no token get identical responses.

### What else we could have done

**Spring MVC interceptors (`HandlerInterceptor`).** These run after MVC has
already chosen which controller will handle the request, which is much later
than a filter. For something like our size limit, which must reject before the
body is read, that's the wrong tool. Interceptors are right when you genuinely
need to know *which handler* is about to run (say, reading a custom annotation
on that method). We never do.

**AOP with an annotation** (`@RateLimited` on methods). More granular, and
declarative. We skipped it because we only ever throttle two URL paths, and a
filter with an `if` handles that with no proxies, no aspect weaving and no
annotation to define and document.

### Java 17 vs Java 8

The filter API predates both, so no framework difference. Where the JDK shows
up is hand-written JSON in the rate limiter:

```java
// Java 17, text block
response.getWriter().write("""
        {"status":429,"error":"RATE_LIMITED","message":"Too many requests, please try again later"}
        """);
```

```java
// Java 8, escape every quote and concatenate
response.getWriter().write(
    "{\"status\":429,\"error\":\"RATE_LIMITED\"," +
    "\"message\":\"Too many requests, please try again later\"}"
);
```

I'll be honest: in the real class that's a one-line string, not a text block,
and it's the *one* place we hand-write JSON instead of serializing an `ApiError`
with the injected `ObjectMapper`. It's a small inconsistency, and it's listed in
the known gaps.

### Where it's still weak

Between our three filters and Spring's own, a request goes through a dozen-plus
classes before it hits a controller, which is why those stack traces look
terrifying. That's normal for Spring Security, but it's harder to reason about
than a simple `if` chain. The cure isn't removing it, it's documentation, which
is what this file and the class comments are for.

---

## 7. Authorization and roles

### Why it matters

Authentication asks "who are you?" Authorization asks "what are you allowed to
do?" People blur those two constantly, and the result is the classic bug where
anyone who's logged in can hit an admin URL just by knowing it.

### What we built

About the simplest RBAC you can have: two roles, `USER` and `ADMIN`, checked per
route.

```java
.requestMatchers("/api/admin/**").hasRole("ADMIN")
.anyRequest().authenticated()
```

The role is a plain string column on `users`. `UserDetailsImpl` turns it into an
authority (`ROLE_ADMIN`), and `hasRole("ADMIN")` matches it. Spring adds the
`ROLE_` prefix for you in `hasRole`; if you use `hasAuthority`, you write the
full `"ROLE_ADMIN"` yourself. People trip on that constantly.

Two details that matter more than they look:

**Order is part of the rule.** Spring evaluates these top to bottom and the
first match wins. The `/api/admin/**` rule must sit above `anyRequest()`, or it
would never be reached.

**No admin signup.** There is deliberately no endpoint that creates an admin. A
self-service "make me an admin" door would be a vulnerability on day one. You
promote someone with one SQL statement, by hand.

### What else we could have done

**ABAC (attribute-based).** Rules like "can edit if the document's department
matches yours, and it's business hours, and it isn't locked." Spring supports
this through `@PreAuthorize` with SpEL, or you can use a policy engine like OPA.
Every decision in this app is either a role check or an ownership check, so a
general policy engine would be solving a bigger problem than we have.

**ACLs (Spring Security ACL).** Per-object grants: "user 47 can read document
12, specifically." This is the right tool when permissions vary object by object,
for example a shared document with some editors and some viewers. Our ownership
rule ("you can touch it if you created it") doesn't need it. If you add "share
this note with someone", you'd want ACLs or a simple `note_shares` table.

**Permission strings** (`notes:write`, `admin:users:list`), composed into roles.
More flexible than two fixed roles. We have two roles and one admin route, so it
would be abstraction for its own sake, which the project brief told us not to
build.

### Java 17 vs Java 8

No difference. `hasRole` is a method call on a builder. The enum you'd use for a
fixed set of roles is identical on both:

```java
public enum Role { USER, ADMIN }
```

We *don't* actually use this. Role is a raw `String`, which means `"ADIMN"` is a
typo the compiler can't catch. An enum with `@Enumerated(EnumType.STRING)` would
fix that, and it's a worthwhile improvement as soon as you have a third role.

### Where it's still weak

The roles are flat: nothing says ADMIN implies USER. That's fine for two roles.
If you ever add a MODERATOR that's a subset of ADMIN, look at Spring's
`RoleHierarchy` instead of duplicating rules. Also, a role change doesn't take
effect until the user's next token, because the role is read when the token is
used to load the user. With a 1-hour access token, demoting someone isn't
instant for up to an hour. For this app that's acceptable, but it's good to
know.

---

## 8. Resource ownership

### Why it matters

A role check says "a USER may call `/api/notes/{id}`". It says nothing about
*whose* note `{id}` is. With only role checks, any logged-in user can walk
`/api/notes/1`, `/2`, `/3` and read the whole table. This is one of the most
common real-world vulnerabilities (it has a name, IDOR), and it's invisible to
anyone who only tests the happy path.

### What we built

Every note query is scoped by the user ID taken from the verified token:

```java
private Long currentUserId() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    UserDetailsImpl principal = (UserDetailsImpl) auth.getPrincipal();
    return principal.getId();
}

@GetMapping("/{id}")
public Note getNote(@PathVariable Long id) {
    return noteRepository.findByIdAndUserId(id, currentUserId())
            .orElseThrow(() -> new ApiException(ErrorCode.RESOURCE_NOT_FOUND, "Note not found: " + id));
}
```

Two ideas make it actually secure rather than "usually fine":

1. **The owner never comes from the request.** Not a path variable, not a query
   param, not a body field. The server already knows who you are from the token
   it just verified, so there's nothing for you to claim.
2. **"Exists but isn't yours" looks identical to "doesn't exist".** Both are a
    404. A 403 would tell an attacker the ID is real, and by watching 403 vs 404
         they could map out which IDs exist and roughly how many notes the system
         holds, without reading a byte of content.

`currentUserId()` reads a field off the principal that was loaded when the JWT
was validated. It doesn't hit the database. That's worth saying because
"current user" helpers in other codebases often do query on every call.

### What else we could have done

**A shared "owned resource" base class or interface** so Notes, Tasks and Files
reuse one scoped-lookup pattern. We deliberately didn't. Repeating a small,
obvious pattern keeps each controller readable on its own, and it means a bug in
a shared base class can't quietly break every resource at once. That's a
judgment call, not a law: at ten resource types instead of three, I'd probably
flip it and share.

**A JPA `@ManyToOne` owner relationship** instead of a plain `userId` column.
We started there and switched on purpose. The relationship brings lazy loading
(touch `note.getOwner()` outside a session and you get a
`LazyInitializationException`) and implicit joins that are easy to misread. A
plain foreign key plus an explicit `WHERE user_id = :userId` is longer, but you
can see exactly what runs.

### Java 17 vs Java 8

No difference at all. It's a private method and a repository query, both plain
since Java 5. I like keeping a section like this in the document, because not
every good practice in the project is about modern syntax. Some of it is just
"write the WHERE clause."

### Where it's still weak

The `currentUserId()` method is copy-pasted across resource controllers, by
design (see above). The bigger risk is human: the pattern only protects the
queries that *use* it. A new endpoint that calls plain `findById(id)` quietly
reintroduces the hole, and nothing but code review will catch it. If that worries
you, an integration test per resource that fetches user A's ID as user B is the
cheap insurance.

---

## 9. CORS

### Why it matters

Browsers enforce a rule called the Same-Origin Policy: JavaScript on
`https://frontend.example.com` can't read a response from
`https://backend.example.com`, because they're different origins, unless the
backend explicitly says that's fine. Notice who this protects. It protects
*users*, not your API. Without it, any website could silently fire requests at
other sites using your logged-in browser and read the answers.

### What we built

An explicit allow-list, one per Spring profile, wired into Spring Security (not
just Spring MVC):

```java
@Bean @Profile("local")
public CorsConfigurationSource localCorsConfigurationSource() {
    return buildSource(List.of("http://localhost:5173"));
}

@Bean @Profile("prod")
public CorsConfigurationSource prodCorsConfigurationSource() {
    return buildSource(List.of("https://your-frontend.vercel.app"));
}
```

We set `allowCredentials(false)` because we authenticate with a bearer token,
not cookies. That matters for a reason people get wrong: browsers flatly refuse
to combine a wildcard origin with `allowCredentials(true)`, since that would
mean "any site can make cookie-carrying requests and read the answer", which is
very close to the attack CORS exists to stop. We don't need credentialed mode at
all.

When a browser sends a request with a custom header like `Authorization`, it
first sends a **preflight**, an `OPTIONS` request asking "is this allowed?". If
your server doesn't answer that correctly, the real request never leaves the
browser. That's why `Authorization` is in our `allowedHeaders`, and why the
CORS config has to be known to Spring Security: the security filters run *before*
MVC, and would otherwise reject the preflight before MVC's own CORS handling
ever saw it.

> **Heads up:** CORS is not authentication and not a firewall. `curl`, Postman
> and any server-side script ignore it completely. It only controls what *a
> browser* will let page JavaScript do. Never rely on it to keep anyone out.

### What else we could have done

**A wildcard (`*`).** Easiest in development, since you never debug a CORS
rejection. The cost is that any site on the internet can attempt requests from
a victim's browser. With bearer tokens the practical risk is lower than with
cookies, but "we'll tighten it before shipping" is the kind of promise that
never gets kept. An explicit list costs nothing at runtime.

**MVC-only CORS** (`WebMvcConfigurer.addCorsMappings`). This is a common mistake
rather than a real alternative, for the filter-ordering reason above.

**Origins from an environment variable.** We started there and switched. An
allowed origin is a public URL, not a secret, so putting it in Java keyed by
profile makes the mapping visible in one file, instead of hidden in a hosting
dashboard. Both are legitimate. I just prefer "obvious from reading the repo"
over "changeable without a redeploy" for a value that rarely changes.

### Java 17 vs Java 8

`List.of(...)` is Java 9+, so on Java 8 you'd write
`Collections.singletonList("http://localhost:5173")` or `Arrays.asList(...)`.
That's the entire difference. It has nothing to do with security.

### Where it's still weak

The production origin is a literal placeholder (`your-frontend.vercel.app`). It
needs a real value before the app faces the internet, and it's the kind of thing
that's easy to ship by accident. If the profile is missing entirely, neither
CORS bean exists and the app refuses to start, which is the loud failure we
want.

---

## 10. CSRF

### Why it matters

CSRF abuses *ambient* credentials, meaning cookies, which browsers attach to a
request automatically no matter which page caused it. You're logged into your
bank, you open a malicious page in another tab, and that page quietly submits a
transfer form to your bank. Your browser helpfully attaches your real session
cookie, and the bank can't tell "you clicked" from "a page tricked your browser."

### What we built

```java
.csrf(csrf -> csrf.disable())
```

Disabled, and I want to be precise about *why*, because "APIs don't need CSRF"
is the lazy answer and it isn't a rule. The reason here is that **we have no
ambient credentials.** Every request needs an `Authorization: Bearer ...` header
that our own frontend JavaScript adds by hand. A malicious page can't make your
browser attach that header on its own, and it can't read the token to forge one,
because the token isn't in a cookie and same-origin policy stops a different
site from reading our site's storage. The attack has nothing to ride on.

### What else we could have done

**Leave it on anyway.** Spring would then want a CSRF token echoed back on every
POST/PUT/DELETE. For a stateless bearer API that adds friction and no protection,
because the thing CSRF tokens defend against can't happen here.

**Double-submit cookie.** A technique for APIs that *do* use cookies but don't
want server-side token state. Irrelevant to us.

### Java 17 vs Java 8

Not applicable. It's one lambda, the same on both.

### Where it's still weak, and when to revisit

This decision is only true while we have no cookie-based auth. If you ever add
an `HttpOnly` session cookie (which, as section 3 says, is a real security upgrade
in some ways), you must turn CSRF protection back on for those routes. The code
comment says exactly that, so a future reader doesn't assume it was forgotten.

---

## 11. Rate limiting

### Why it matters

With no limit, a script can try thousands of passwords a minute against one
account, or create junk accounts all day. Every other control, hashing, tokens,
ownership, is undermined if the front door to getting a credential has no
friction. This is also a *resource* problem: remember BCrypt is deliberately
expensive, so a flood of login attempts costs us real CPU.

### What we built

An in-memory, per-IP token bucket (Bucket4j) on `/api/auth/login` and
`/api/auth/register` only, 5 requests a minute per IP, stored in a bounded,
self-evicting Caffeine cache.

```java
Bandwidth limit = Bandwidth.classic(5, Refill.greedy(5, Duration.ofMinutes(1)));
```

Think of a bucket holding 5 tokens. Each request takes one. When it's empty
you're told to wait, and it refills over time. "Greedy" refill means all 5 come
back together rather than one every 12 seconds; it's simpler to reason about.

We only throttle those two paths on purpose. A logged-in user hitting
`/api/notes` repeatedly is just using the app.

The first version had a real bug: it stored buckets in a plain
`ConcurrentHashMap` that never evicted anything, so an attacker could grow
memory forever just by sending one request from each of many IPs, without ever
tripping the limit. The fix swapped it for Caffeine with `expireAfterAccess` and
a `maximumSize`. The history of both commits is worth reading, because the bug
is a good example of a "security feature" that was itself an attack surface.

### What else we could have done

**Resilience4j's `RateLimiter`.** Good, but it's a piece of a bigger toolkit
(circuit breakers, retries, bulkheads) that we don't otherwise use. Bucket4j is
narrower, which made it the lighter dependency for one capability.

**Guava's `RateLimiter`.** Built to *pace outgoing calls* ("don't hit this API
faster than N per second"), not to *reject incoming requests with a clean HTTP
response*. Same algorithm family, wrong shape of tool.

**An API gateway or CDN** (Cloudflare, Kong, AWS API Gateway) doing this before
traffic reaches the JVM at all. This is genuinely the more robust production
answer, because floods get stopped before they cost you CPU, and gateways can do
IP reputation and cross-instance coordination. We don't have one in front of
this service, so application-level limiting is what exists, and it's documented
as a stopgap.

### Java 17 vs Java 8

Bucket4j and Caffeine use ordinary builder APIs, so there's no JDK difference.
The line `buckets.get(clientIp, ip -> newBucket())` uses a lambda, which shipped
in Java 8, so it's identical on both. It's a good reminder that "Java 8 vs 17"
isn't one cliff. Lambdas (8), `var` (10), text blocks (15), records and pattern
matching (16) and sealed classes (17) each landed separately.

### Where it's still weak

Every one of these is also written at the top of `RateLimitFilter.java` and in
`docs/adr/002-rate-limiting.md`:

- **IP is a weak identity.** Everyone behind one NAT or office network shares an
  address, so one bad actor can lock out the rest. A botnet or proxy pool
  trivially rotates addresses.
- **Behind a proxy it may be wrong.** On a platform like Render, `getRemoteAddr()`
  can return the *proxy's* IP, so every user looks like the same person, unless
  `X-Forwarded-For` is parsed correctly. We don't parse it. **Test this at deploy
  time.** It's the most likely thing to bite.
- **Not distributed.** Each instance keeps its own buckets, so two instances
  double the effective limit.
- **No graduated response.** A real user who mistypes five times is treated like
  an attacker. There's no CAPTCHA fallback.
- **Per-account protection doesn't exist.** One account hit from many IPs isn't
  slowed at all. Account lockout is the complementary defense, which we looked at
  and chose not to build yet (it lets an attacker lock a victim out on purpose,
  and we have no email to tell the victim).

---

## 12. Security response headers

### Why it matters

Browsers have a whole set of protective behaviors that only switch on when the
server asks for them with the right response headers. Without them, the browser
falls back to permissive legacy defaults from before those protections existed.

### What we built

We set each header explicitly in `SecurityConfig`, with the reason next to it, so
removing one later means overriding a documented decision rather than deleting a
mystery line.

**`X-Content-Type-Options: nosniff`**. Stops the browser from guessing a
response's type by peeking at its bytes and ignoring the `Content-Type` we sent.
It matters most for anything that started life as user input (a future file
upload): without it, bytes we labelled `image/png` that happen to look like HTML
could get rendered and run as a page.

**`X-Frame-Options: DENY`**. Our responses can't be put inside an `<iframe>` on
another site. That blocks clickjacking, where an invisible frame of a real page
sits under a fake button. We're a JSON API with no page that frames itself, so
`DENY`, not `SAMEORIGIN`.

**`Strict-Transport-Security`** (HSTS, one year, with subdomains). Tells browsers
"never talk to this host over plain HTTP again", which defeats SSL-stripping,
where someone on the network intercepts the *first* plain-HTTP request before it
would have upgraded. Browsers ignore HSTS received over plain HTTP, so you will
**not** see it on `localhost`. That's correct, not a bug.

**`Referrer-Policy: strict-origin-when-cross-origin`**. Full URL for same-origin
navigation, only the origin (no path, no query) cross-origin, nothing at all on an
HTTPS-to-HTTP downgrade. It stops a URL that happens to contain something
sensitive from leaking to a third party.

**`Cache-Control: no-cache, no-store, must-revalidate`**. A Spring Security
default we kept and documented instead of overriding. It stops proxies and the
browser's disk cache from keeping responses that might hold tokens or personal
data.

### What we deliberately did not set

**`Content-Security-Policy`.** It's arguably the most powerful anti-XSS header
there is, and we leave it off *on purpose*. CSP tells a browser which script,
style and image sources an **HTML page** may load. This backend never serves HTML,
so a CSP header on a JSON response does essentially nothing. It belongs on the
frontend, wherever the real HTML lives. I'm writing this down so nobody
flags its absence as an oversight in a security review.

**`X-XSS-Protection`.** A legacy header for a browser feature that no longer
exists in any major browser, and OWASP now says not to set it, because in old
browsers that still honoured it, it could be abused to *suppress* legitimate
content. Rely on CSP (on the frontend) instead.

### What else we could have done

Setting headers by hand in a `Filter`. We already have three custom filters, and
the `.headers(...)` DSL is the framework's own supported route, maintained
alongside Spring Security, with no filter-ordering to reason about.

### Java 17 vs Java 8

None. It's fluent builder configuration, unrelated to the language version.

### Where it's still weak

We don't set `Permissions-Policy` (camera, mic, geolocation). A JSON API has no
use for those, but it's another one to confirm on the frontend.

---

## 13. Error handling and what we refuse to say

### Why it matters

Every error response is intelligence for an attacker. "Wrong password" versus "no
such user" reveals who's registered. A stack trace hands over framework versions,
class names and sometimes SQL fragments. But a bare "500" with nothing else makes
*your* debugging miserable. The way out is to split the audiences: the client
gets something generic, and the server logs everything.

### What we built

One enum, `ErrorCode`, ties each failure to an HTTP status, a machine-readable
string and a default message. `ApiException(ErrorCode, message)` is the single
exception type you throw. (`ARCHITECTURE.md` explains why this replaced a class
per failure.)

The specific things we refuse to say, and why:

- **Bad password and unknown email look the same.** Otherwise anyone can enumerate
  which emails are registered.
- **Someone else's note and a missing note are both 404.** See section 8.
- **The catch-all handler never sends `ex.getMessage()` to the client.** It logs
  it, with the whole stack trace at ERROR, and the client sees "Something went
  wrong". This is the most important line in the error system. Every other
  handler is specific and safe by construction, but the catch-all exists so a bug
  you didn't foresee can't leak an internal detail through a default message.
- **403s don't name the missing role.** "You do not have permission" is enough.
  "You need ROLE_ADMIN" is a shopping list for an attacker.
- **Unknown routes are 404s, not 500s.** Spring throws `NoResourceFoundException`
  for a URL nobody handles. Until we mapped it, our catch-all turned a typo'd URL
  into a 500 with a full stack trace and an ERROR log line, so every scanner that
  poked at us looked like an outage.

### What else we could have done

**RFC 7807 "Problem Details".** There's a standard JSON shape for API errors
(`type`, `title`, `status`, `detail`, `instance`), and Spring 6 supports it through
`ProblemDetail`. We rolled our own `ApiError` because we started before settling
on it and it does everything we need. Starting fresh today I'd look hard at
`ProblemDetail` for tooling interoperability. What gets *included* is the security
decision either way, whichever envelope you wrap it in.

**One validation code per kind of failure** (missing, too long, wrong format). We
use a single `VALIDATION_ERROR` with a field-specific message. Finer codes are
low-risk and would be a fine upgrade. We just never had a frontend that needed to
branch on them.

### Java 17 vs Java 8

`ApiError` is a record:

```java
public record ApiError(Instant timestamp, int status, String error, String message, String path) {
    public static ApiError of(ErrorCode code, String path) { /* ... */ }
    public static ApiError of(ErrorCode code, String message, String path) { /* ... */ }
}
```

Records aren't a security feature, but there's a genuine side benefit: every field
is `final` and there are no setters, so nobody can later add a convenient
`setMessage()` and let some downstream filter append debug text to an
already-built error before it goes out. On Java 8 that setter is one careless
edit away.

### Where it's still weak

> **Known gap:** a failed login currently produces a **500**, not a 401. The
> `BadCredentialsException` thrown inside the login controller isn't an
> `ApiException`, so it falls through to the catch-all handler. It was left alone
> deliberately in an early commit with a note to fix it, and it never got fixed.
> The fix is one handler for `AuthenticationException` returning
> `ErrorCode.UNAUTHORIZED` (with the same generic message, so we don't leak which
> part was wrong). Do this before you ship.

Also, when you add a new exception handler, double-check that you never route a
caught internal message into the *client-facing* `ApiError` instead of only the
log line. The two code paths look similar, and it's an easy slip.

---

## 14. Actuator

### Why it matters

Actuator is wonderful for operations (health checks, metrics, changing log levels
live) and dangerous if exposed casually. `/actuator/env` can expose configuration,
`/actuator/beans` maps your internals for anyone probing for a way in, and
`/actuator/heapdump` produces a full memory snapshot that can contain a live JWT
secret and password hashes. "We'll lock it down later" is how those end up public.

### What we built

Two independent locks. Leaking something needs *both* changed:

1. **`management.endpoints.web.exposure.include`** decides what exists over HTTP at
   all. In prod it's `health,info,metrics`. Anything else isn't registered, so it
   returns our own 404. That's stronger than a 401 or 403, which would at least
   confirm something is there.
2. **`SecurityConfig`**: `/actuator/health/**` is public, because a platform
   health checker has no token, and everything else under `/actuator/**` needs
   ADMIN.

`heapdump` and `shutdown` are never exposed anywhere, even behind the admin check.
"An admin token" isn't a high enough bar for a file that contains your secrets.

The health endpoint also split into **liveness** (is the JVM alive?) and
**readiness** (can it serve traffic, including the database?). Liveness must not
depend on Postgres: if the database blips and a platform restarts services on
failed liveness, it would reboot a perfectly healthy JVM for nothing.

> **A bug worth remembering:** my first version of the properties had both
> `include=health` and `exclude=*`. In Spring Boot, `exclude` beats `include`, so
> that removed `health` too and `/actuator/health` fell through to the
> static-resource handler. Keep it simple: use an `include` list and don't use
> `exclude` unless you mean it.

### What else we could have done

**A separate management port** (`management.server.port`) so actuator lives on a
port you never expose publicly. That's the more robust pattern for a classic
server. We don't use it because Render routes a single public port, and its own
health check has to reach `/actuator/health` on that same port.

**HTTP Basic just for actuator.** Common where there's no other auth system to
reuse. We already have role-based JWT, so a second credential scheme only for
operations would be extra surface for no gain.

### Java 17 vs Java 8

None. It's properties files and the Security DSL.

### Where it's still weak

`show-details=never` in production means even a legitimate admin sees only
`UP`/`DOWN` on the health endpoint, not *which* component failed. That's the right
default for what an anonymous caller should see, but real diagnosis means reading
logs and `/actuator/metrics`. Don't expect the health body to tell the story.

---

## 15. Request size limits

### Why it matters

Nothing stops a client from sending an enormous body. Jackson will try to buffer
and parse whatever arrives, so a handful of big concurrent requests can use up
memory *during deserialization*, before any of your `@Valid` checks get a chance
to say no.

### What we built

A custom filter, `RequestSizeLimitFilter`. Here's the part that surprises people:
**Spring Boot has no property that caps a plain JSON body on Tomcat.** The
`spring.servlet.multipart.*` settings only govern file uploads, which is a
completely separate code path. The filter works in two layers, because either one
alone can be dodged:

1. If the declared `Content-Length` is over the limit, reject with 413 before
   reading a single byte.
2. Otherwise wrap the input stream in a counter that throws the moment real bytes
   exceed the limit. That catches chunked requests (no declared length) and
   clients that lie about it.

On top of that, field-level `@Size` limits: note title 255 (matching the
`VARCHAR(255)` column), note content 100,000, email 254, password 8 to 72. Before
those existed, a 300-character title passed validation, hit Postgres, and came
back as a **500**: a client mistake reported as our fault, and noise in the ERROR
logs. Passwords cap at 72 because BCrypt only looks at the first 72 bytes, so
accepting megabytes just means reading and hashing junk.

Multipart is switched **off** (`spring.servlet.multipart.enabled=false`) until a
file endpoint exists. If you leave it on, multipart parsing happens inside the
servlet container, bypassing our counting stream, and can write temp files to
disk. When you do build uploads, use limits like these and exempt that path from
the 1MB JSON cap:

```properties
spring.servlet.multipart.enabled=true
spring.servlet.multipart.file-size-threshold=2KB   # in memory below this, temp file above
spring.servlet.multipart.max-file-size=10MB        # per file
spring.servlet.multipart.max-request-size=15MB     # whole request
```

### What else we could have done

**Switch to Undertow**, which has a native `server.undertow.max-http-post-size`.
Valid, but changing embedded servers is a bigger move than adding one filter, and
this repo should show the far more common Tomcat setup.

**A reverse proxy limit** (nginx `client_max_body_size`, or the platform's
equivalent) so oversized requests never reach the JVM at all. Strictly better for
resource protection, and I'd add it as defense in depth if your host offers it. We
don't have one in front of this service, so the filter is the only layer today.

### Java 17 vs Java 8

The `CountingInputStream` is an ordinary class overriding abstract methods. It
looks the same on both versions. Not every piece of code needs modern syntax, and
sometimes a plain class is the right unglamorous tool.

### Where it's still weak

One flat 1MB cap for all JSON endpoints. A future endpoint with genuinely large
text needs a path-specific override, and the filter's own comment says so, so
nobody has to find the ceiling the hard way. Also, slow-dribble attacks (a client
sending one byte every few seconds) are only covered by Tomcat's default
connection timeouts.

---

## 16. Secrets

### Why it matters

A secret committed to git is compromised *forever*. Deleting it in a later commit
doesn't help, because history keeps every version and anyone who ever cloned or
could read the repo can find it. This is a different category from a normal bug
you can fix going forward.

### What we built

Every genuine secret (`DATABASE_PASSWORD`, `JWT_SECRET`) is read through a
`${VAR_NAME}` placeholder from an OS environment variable and never has a default
in any committed file. If a placeholder can't be resolved, Spring fails at
startup with an error naming the missing property. That's on purpose: fail loud
rather than quietly start with something broken or insecure.

The line we draw: **secrets go in the environment, plain configuration goes in the
repo.** CORS origins, rate limits, retention durations and size limits aren't
confidential, and keeping them committed means a change shows up in `git log` and
code review, which is a real benefit for non-secret values. Don't put something in
an environment variable just because it feels more "professional". Put it there
because it would hurt if someone read it.

> **Never commit a `.env` file**, not even one with placeholder-looking values.
> Someone will paste a real value into it one day. Set variables in your IDE run
> configuration or your shell, and document them (see `CONFIGURATION.md`).

### What else we could have done

**A real secrets manager** (AWS Secrets Manager, Vault, Google Secret Manager).
These give you rotation, access audit logs ("who read this and when") and one
place to manage values across services, instead of pasting the same value into
several dashboards. We use plain environment variables because one service doesn't
justify that overhead yet, and it's a very reasonable thing to adopt as you grow.

**Spring Cloud Config with encrypted properties.** The Spring-native way to
centralize configuration across services. Same reasoning: real value at multi-service
scale, overhead at one.

**A `.env` loader** such as `dotenv-java`. Convenient locally, but it leaves a file
in the project directory that is one stray `git add .` from being committed. "Just
remember to gitignore it" has a long track record of failing for someone eventually.

### Java 17 vs Java 8

None. Placeholder resolution is a Spring property-source feature, unrelated to the
JDK.

### Where it's still weak

No rotation for either secret. Rotating the database password means updating the
variable and restarting. Rotating `JWT_SECRET` also logs every user out at once,
and there's no graceful transition (see section 4 on `kid`).

---

## 17. Logging as a security tool

### Why it matters

We made the *client* see almost nothing on failure. If the server also recorded
almost nothing, we'd have locked ourselves out of our own investigations. Logs are
where the detail we refuse to show the client goes.

### What we built

Every failure path logs, independent of what the client receives, at a level that
matches how much it matters:

- **ERROR** is for the genuinely unexpected: the catch-all, database exceptions.
  We pass the whole exception object to the logger, not just `getMessage()`, so
  SLF4J prints the full stack trace and cause chain. That's exactly the detail we
  won't send to a client.
- **WARN** is for expected-but-notable events: authentication failures, access
  denied, rate-limit rejections. These aren't bugs, but you want to be able to
  search and count them.
- **INFO** is for routine noise: validation failures, 404s on unknown routes. Kept,
  but not loud enough to bury real problems.

Database exceptions get extra care. `ex.getMessage()` on a wrapped SQL failure is
often just `could not execute statement`, which tells you nothing. The useful part
(the SQLState code and the real driver message) lives deeper in the cause chain,
so the handler walks the chain and logs `sqlState` and the root message as
separate fields you can grep or alert on. (We checked this with a small experiment
rather than trusting memory. The detail isn't lost with plain stack-trace logging,
it's just buried and unsearchable.)

### What else we could have done

**Writing failures into a database table**, so you can query "every failed login
for this user last month". We deliberately didn't. It means your error handling
writes to the *same database* that may be the thing failing, from *inside* the
request that's already failing, so a DB problem can now throw a fresh error from
within your error handler and hide the original. If you genuinely need a queryable
audit trail, make it an async, best-effort write (a queue or a separate
write-behind), never inline in the request path.

**Structured JSON logging.** Better if you feed logs into Datadog, Elasticsearch or
Loki, since they index named fields much better than they parse formatted text.
SLF4J's parameterized messages (`ip={} path={}`) are structured *enough* to grep
today without a new dependency. Worth upgrading once real aggregation tooling shows
up.

### Java 17 vs Java 8

SLF4J predates both, so nothing differs. The only visible help from Java 17 is the
cleaner cause-chain code from pattern-matching `instanceof` (section 5).

### Where it's still weak

There's no request ID. A common pattern is to generate a UUID per request, put it
in the SLF4J MDC, and have every log line carry it, so you can filter for
"everything that happened during this one bad request". Today you correlate by
timestamp and guesswork. It's a cheap, high-value addition. Also, never log tokens,
passwords or full `Authorization` headers. We don't, and the first person to add
`log.debug("request: {}", request)` should be stopped in review.

---

## 18. Java 17 features used here

A single reference for every place this project leans on something newer than Java
8, so you know what you'd lose by going back.

**Records (16).** Used for `ApiError`, `LoginRequest`, `RegisterRequest`,
`RefreshRequest`, `LoginResponse`, `CreateNoteRequest`, `IssuedToken`. All are pure
data carriers: build, read, never mutate. On Java 8 each becomes a full class with
private final fields, a constructor, getters, and hand-written `equals`, `hashCode`
and `toString`. Small gotcha when porting: record accessors are `email()`, not
`getEmail()`, and Jackson handles both, but your own calling code won't.

**Pattern matching for `instanceof` (16).** The cause-chain walks in the exception
handlers. Pure readability; it removes the cast line.

**`var` (10).** Used lightly, such as in the JWT filter. Local type inference only,
identical bytecode.

**Text blocks (15).** Used for the multi-line SQL in `@Query`. On Java 8 you'd
concatenate quoted lines with `\n`, which gets unreadable for SQL.

**Not used, and worth knowing:** enhanced `switch` expressions (14) and sealed
classes (17). Our control flow around `ErrorCode` and `TokenType` doesn't need
them. Sealed types would be a fit if error categories ever became a real type
hierarchy carrying different data, instead of a flat enum.

**What it all adds up to.** None of these change what the app *does* securely. They
cut boilerplate. If you maintain a Java 8 codebase and read this for guidance,
every decision in sections 1 to 17 applies unchanged. You'll just type more lines
to say the same thing.

---

## 19. Decision table

| Concern | We chose | Main alternative | Why not (short version) |
|---|---|---|---|
| Password hashing | BCrypt | Argon2 | BCrypt is built in and well known; Argon2 is arguably stronger and fine for new projects |
| Session vs token | Stateless JWT | Sessions + Spring Session/Redis | Expected separate frontend origin and multiple instances; Redis sessions are a legitimate, often better choice for same-origin apps |
| JWT signing | HMAC (HS256) | RSA / EC | One process issues and verifies; asymmetric matters once many services verify |
| JWT library | jjwt | Nimbus JOSE+JWT | Friendlier API for a readable repo; Nimbus for encrypted tokens |
| Refresh strategy | Rotating refresh tokens | None, re-login on expiry | All-day-session use case justified it; many apps don't need it |
| Authorization | Flat RBAC, 2 roles | ABAC / ACL / permission strings | Only two roles and one admin route exist |
| Ownership | `user_id` column + scoped native query | `@ManyToOne` + shared base class | Visible SQL, no lazy-loading surprises, self-contained controllers |
| Rate limiting | In-memory per-IP (Bucket4j) | Gateway / Redis limiter | Single instance, no hostile traffic yet; documented stopgap |
| CSRF | Disabled | Enabled with tokens | No ambient credentials to exploit |
| CORS | Per-profile allow-list in Java | Env-var origins / wildcard | Public URLs, not secrets; wildcard is too open |
| Actuator | Allow-list + admin role | Separate management port | Render exposes one public port |
| Request size | Custom filter + `@Size` | Undertow property / proxy limit | No Tomcat property exists; add a proxy limit too if you can |
| Schema | Manual SQL | Flyway / Liquibase | Teaching choice; **use a migration tool on real team projects** |
| Secrets | OS environment variables | Vault / cloud secrets manager | One service doesn't justify the overhead yet |
| Logging | SLF4J to stdout | DB-backed audit table | Don't tie error handling to a database that may be failing |

---

## 20. Known gaps

Everything I know is unfinished, in one list, roughly by how soon I'd fix it.

1. **Failed login returns 500, not 401.** Add a handler for
   `AuthenticationException`. Fix before shipping. (Section 13.)
2. **`X-Forwarded-For` isn't parsed.** Behind Render, the rate limiter may treat
   every user as one IP. Verify at deploy time. (Section 11.)
3. **Production CORS origin is a placeholder.** (Section 9.)
4. **No request ID in logs.** Cheap and valuable. (Section 17.)
5. **No "log out everywhere".** One query. (Section 5.)
6. **No refresh-token family revocation.** Needs a way to notify users first.
   (Section 5.)
7. **No JWT key rotation (`kid`).** (Section 4.)
8. **`DelegatingPasswordEncoder` isn't used**, so no painless BCrypt upgrade path.
   (Section 1.)
9. **Role is a raw string, not an enum.** (Section 7.)
10. **No account lockout.** A conscious decision, not an oversight; revisit if you
    add email. (Section 11.)
11. **One hand-written JSON string in `RateLimitFilter`.** Minor inconsistency.
    (Section 6.)
12. **Manual schema management.** Fine for learning, wrong for a team. (Section 19.)

---

## One last thing

If you're taking this repo as a base for something real, read the "where it's
still weak" part of every section that touches your use case *before* you ship,
not after. A security document that only tells you what's good isn't doing its
job, and I'd rather you find the holes in a markdown file than in production.