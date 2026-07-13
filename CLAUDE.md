# Project Rules

## Architecture

- Runtime: Cloudflare Workers. All code must be compatible with Workers runtime (no Node.js-only APIs).
- Framework: Hono with OpenAPIHono. All routes use `createRoute()` + `app.openapi()`.
- Database: Cloudflare D1 via Drizzle ORM. No raw SQL concatenation — use Drizzle query builder or `sql` template tag.
- Rate limiting: Cloudflare KV with sliding window.
- Sessions: cookie-based, stored as SHA-256 hash in D1.

## Route Pattern

Every new route must follow this structure:
1. Define `createRoute()` with OpenAPI metadata (tags, summary, request/response schemas)
2. Apply `requireAuth` via `use()` for protected routes
3. Call `checkPermission(c, "resource:action")` as first line in handler for RBAC-protected routes
4. Use service layer for business logic — no DB queries in route handlers

## Security Requirements (enforced by 131 tests)

All new code must pass these checks:

### Input
- Validate ALL input with Zod schemas (registered via OpenAPI createRoute)
- Sanitize user-provided text with `stripHtmlTags()` from `utils/sanitize.ts` — strips HTML tags, UTF-7 patterns, null bytes, CRLF
- Normalize emails with `normalizeEmail()` — lowercase + trim
- Email max length: 254 chars (RFC 5321)
- Password: min 8, max 128 chars
- Pagination: clamp page >= 1, limit 1-100

### Authentication & Sessions
- Session cookie: HttpOnly, Secure, SameSite=Lax, Path=/
- Session token: 32 random bytes via `crypto.getRandomValues()`, stored as SHA-256 hash
- Deactivated users (`is_active = false`) must be rejected at session validation
- Users cannot delete themselves (self-deletion protection)

### Authorization
- Use `checkPermission(c, "resource:action")` — format is `resource:action`
- Admin role bypasses all permission checks
- Permissions checked live from DB on every request (no caching)
- New resources need seed permissions: create, read, update, delete

### Error Handling
- All errors must follow format: `{"error": {"code": "UPPER_SNAKE_CASE", "message": "..."}}`
- Never expose stack traces, Zod schema details, or internal error messages
- `HTTPException` caught and returned as 400 with generic message
- `ZodError` caught and returned as `VALIDATION_ERROR` with generic message

### WAF (Web Application Firewall)
- WAF middleware runs before all other middleware
- Blocks SQL injection patterns in query params and POST/PUT/PATCH body
- Blocks XSS patterns in query params (script tags, javascript:, event handlers, eval, document.cookie)
- Blocks path traversal (encoded ../, ..\)
- Blocks known scanner user-agents (sqlmap, Nikto, Nessus, w3af, Havij)
- Returns `{"error":{"code":"FORBIDDEN","message":"Request blocked"}}` with 403
- Must not block legitimate input (names with apostrophes, normal queries)

### Structured Logging
- Every request gets a unique `X-Request-Id` header (16-char hex)
- Logs are JSON structured: requestId, method, path, status, duration, ip, userId, userAgent, cfRay, timestamp
- Log levels: info (<400), warn (4xx), error (5xx)
- Use `requestId` for tracing issues across logs

### Rate Limiting
- Auth endpoints: 5 req/min
- API endpoints: 60 req/min
- Rate limit key: `cf-connecting-ip` only (never `x-forwarded-for` — spoofable)
- Path normalized before rate limit key: URL-decoded, slashes collapsed, dot segments removed

### Security Headers (applied globally)
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
- Permissions-Policy: camera=(), microphone=(), geolocation=()
- HSTS + CSP in production only

### Production
- HTTPS enforced via `cf-visitor` header redirect (301)
- `/doc` and `/docs` return 403 in production
- CORS restricted to whitelisted origins in production

### Account Security
- Account locked after 5 failed login attempts in 15 minutes (429)
- Login attempts recorded in `login_attempts` table
- All auth events logged in `audit_log` table (register, login, logout + IP)

## Database Changes

- Define tables in `src/db/schema.ts` using `sqliteTable()` from Drizzle
- Run `npm run db:generate` to create migration
- Apply locally: `npm run db:migrate:local`
- Apply remote: `npm run db:migrate:remote` (also runs in CI/CD)
- Update `src/__tests__/setup.ts` `applyMigrations()` with new CREATE TABLE statements
- Seed data goes in `drizzle/seed.sql` with `INSERT OR IGNORE` for idempotency

## Testing

- Every feature needs tests. Every security fix needs a regression test.
- Tests run in Cloudflare Workers runtime via `@cloudflare/vitest-pool-workers`
- Use `createMockEnv(env.DB)` per test/section for fresh KV (avoids rate limit interference)
- Use `registerAdminUser()` helper when admin access needed
- Test file naming: `feature.test.ts` for features, `security-*.test.ts` for security
- Run: `npm test`

## CI/CD

- Push to `main` -> GitHub Actions: test -> migrate -> deploy
- Push to PR -> GitHub Actions: test only
- All 131+ tests must pass before deploy

## Adding a New Resource (checklist)

1. Schema: add table in `src/db/schema.ts` + relations
2. Migration: `npm run db:generate` + update test setup
3. Seed: add default permissions to `drizzle/seed.sql` (`perm_{resource}_create/read/update/delete`)
4. Validators: `src/validators/{resource}.schema.ts` with OpenAPI metadata
5. Service: `src/services/{resource}.service.ts` — sanitize inputs, check constraints
6. Routes: `src/routes/{resource}.routes.ts` — OpenAPI routes + `checkPermission()`
7. App: register in `src/app.ts` with `app.route()` + rate limit middleware
8. Tests: feature tests + security regression tests
9. Audit: add `auditService.log()` calls for write operations
