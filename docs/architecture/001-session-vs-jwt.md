# ADR 001: Stateful sessions vs. stateless JWT

## Context
The application currently uses HTTP session authentication (Spring
Security's default model, explicitly configured in a prior commit).
Login creates a server-side session; a `JSESSIONID` cookie ties
subsequent requests back to that session.

The project's target architecture is:
- frontend deployed separately (Vercel)
- backend deployed separately (Render/aws)
- backend potentially scaled across multiple instances

## Decision
Move from session-based authentication to stateless JWT authentication.

## Why sessions become awkward here
- A session lives on whichever backend instance created it. Without
  externalizing session storage (e.g. Redis), a load-balanced deployment
  can't reliably route a request back to the instance holding that
  session.
- Cross-origin cookie behavior (SameSite, browser cookie policies)
  adds friction when frontend and backend are on different domains,
  compared to sending a bearer token in a header.

## Why sessions are NOT being called "wrong"
- Cookies get `HttpOnly` for free — a JWT stored in JS-accessible
  storage does not, unless deliberately mitigated.
- A single-instance, same-origin app has no real reason to give up
  the simplicity of sessions.
- This decision is about this project's specific deployment shape,
  not a universal rule.

## Consequence
The application will move to `SessionCreationPolicy.STATELESS`.
Authentication state will no longer be held server-side; each request
must carry a JWT proving identity independently. This requires:
- JWT generation after login
- JWT validation logic
- a filter that authenticates each request from the token