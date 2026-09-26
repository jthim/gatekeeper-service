# Gatekeeper Service

A Spring Boot authentication/authorization gateway built around Microsoft Entra ID (Azure AD) OIDC login, with
role-based access control, rate limiting, and audit logging designed from the start rather than bolted on.

This project exists to demonstrate secure-by-default application design: every access decision is enforced server-side,
every security-relevant event is logged, and every trust boundary (proxy, CDN, third-party auth) is handled explicitly
rather than assumed.

## Security Features

- **OIDC login via Microsoft Entra ID** — Login, token validation, and session
  establishment are delegated entirely to Spring Security's OAuth2/OIDC client and Microsoft's identity platform.
- **Role-based access control, enforced at the method level** — `@PreAuthorize` on each protected endpoint (
  `IndexController`) checks the caller's Entra ID app role before the method body ever runs, not just at the URL-routing
  layer.
- **Proxy-aware rate limiting** — a token-bucket limiter (`RateLimitingFilter`, via bucket4j) throttles requests per
  client IP. Client IP resolution only trusts the `X-Forwarded-For` header when the direct connection comes from a
  configured, trusted proxy IP (`app.trusted-proxies`) — preventing IP spoofing via a forged header, and avoiding the
  common mistake of collapsing every user behind a load balancer into one shared bucket.
- **Security event logging** — failed OIDC logins, 403 authorization denials, and rate-limit violations are all logged
  with the acting IP/principal, giving an actual audit trail instead of silent failures.
- **Fail-safe redirect handling** — an authenticated user with no recognized app role is routed to a real error page and
  logged as an anomaly, rather than redirected to a dead link.
- **CSRF protection left on** — Spring Security's default CSRF protection is intentionally not disabled; Thymeleaf forms
  carry CSRF tokens automatically via `thymeleaf-extras-springsecurity6`.
- **Supply-chain-conscious front end** — the CDN-loaded Tailwind script is pinned to an exact version with a Subresource
  Integrity (SRI) hash, so a compromised or altered CDN file is rejected by the browser instead of silently executed.
- **Content-Security-Policy, currently set to report-only to observe** — a CSP restricting script/style sources,
  disallowing
  plugins, and locking down `form-action`/`base-uri`/`frame-ancestors` (defense-in-depth against injected content even
  where the app has no current known XSS) using `Content-Security-Policy-Report-Only`. Violations are sent
  to `CspReportController` and logged into the same audit trail as auth failures and access denials, rather than to a
  third-party service. See Known Limitations for the plan to move this to enforcing.
- **No secrets in source control** — Azure credentials are pulled from environment variables (`AZURE_TENANT_ID`,
  `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`); `application.properties` is gitignored, and
  `example.application.properties` documents the required shape without real values.

## Architecture

```
Browser
  │
  ▼
RateLimitingFilter          ← per-IP token bucket, runs before auth
  │
  ▼
Spring Security filter chain
  │  ├─ oauth2Login()        ← Entra ID OIDC, RoleBasedSuccessHandler picks landing page by role
  │  ├─ exceptionHandling()  ← logs + redirects on 403
  │  └─ logout()             ← invalidates session, clears cookies
  │
  ▼
IndexController (@PreAuthorize per route)
  │
  ▼
Thymeleaf views (index / dashboard / admin-dashboard / error)
```

**Stack:** Java 25, Spring Boot 4.1, Spring Security + OAuth2 Client, Spring Cloud Azure (Active Directory starter),
Thymeleaf, bucket4j + Caffeine for rate limiting, JUnit 5 + Spring Security Test.

## Running Locally

1. **Register an app in Microsoft Entra ID** (Azure Portal → App registrations) and define two app roles: `ROLE_ADMIN`
   and `ROLE_USER`. Assign yourself one of them under Enterprise Applications.
2. Copy `example.application.properties` to `application.properties` (this file is gitignored and never committed).
3. Set the following as environment variables (do **not** hardcode them):
   ```
   AZURE_TENANT_ID=<your tenant id>
   AZURE_CLIENT_ID=<your app registration's client id>
   AZURE_CLIENT_SECRET=<a client secret you generate on the app registration>
   ```
4. Run it:
   ```
   ./gradlew bootRun
   ```
5. Visit `http://localhost:8080` and log in — you'll land on `/dashboard` or `/dashboard/admin` depending on your
   assigned role.

## Testing

```
./gradlew test
```

Tests cover the security filter chain configuration, rate-limit exhaustion/recovery behavior, and role-based redirect
logic (`SecurityConfigTest`, `RateLimitingFilterTest`, `RoleBasedSuccessHandlerTest`).

## Known Limitations / Production Considerations

Being upfront about trade-offs made for a portfolio-scope project:

- **Rate limiting is in-memory (Caffeine)**, scoped to a single instance. Running multiple instances behind a load
  balancer would multiply the effective limit. A production deployment would move this to a shared store (e.g. Redis).
- **`app.trusted-proxies` must be configured for your actual deployment target** before going to production — it
  defaults to `localhost` for local development only. See `example.application.properties`.
- **CSP is deployed in report-only mode, not yet enforcing.** `Content-Security-Policy-Report-Only` logs what would be
  blocked without actually blocking it — the deliberate first step before enforcing, so a misconfigured policy doesn't
  break the app for real users. Once violation reports come back clean across normal usage, the next step is dropping
  `.reportOnly()` in `SecurityConfig` to make the policy enforcing.

## License

MIT — see `LICENSE`.