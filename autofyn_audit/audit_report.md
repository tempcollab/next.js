# Next.js Security Audit Report

## Executive Summary

This audit examined Next.js commit `007051470157d38058730ffa0a1983d4b4106424` (v16.3.0-canary.29) for security vulnerabilities. Three issues were identified and confirmed against live instances in a Docker-based test environment:

| ID | Title | Severity |
|----|-------|----------|
| VULN-1 | SSRF via Image Optimizer Redirect (remotePatterns bypass) | High |
| VULN-2 | Auth Bypass via Internal Header Injection (NEXT_PRIVATE_TEST_HEADERS) | High |
| VULN-3 | Server Actions Execute Without Origin Header (defense-in-depth gap) | Medium |

All three vulnerabilities are independently reproducible using the provided exploit scripts.

---

## Scope

- **Repository:** next.js
- **Commit:** `007051470157d38058730ffa0a1983d4b4106424`
- **Version:** 16.3.0-canary.29
- **Testing Environment:** Docker containers on a private bridge network (`audit-net`)
- **Test Mode:** Production (`next build` + `next start`)
- **Testing Date:** 2026-05-26

---

## VULN-1: SSRF via Image Optimizer Redirect (remotePatterns bypass)

**Severity:** High

**Affected Code:**
- `packages/next/src/server/image-optimizer.ts:454` — `validateParams` checks `hasRemoteMatch` on the initial URL only
- `packages/next/src/server/image-optimizer.ts:909-928` — `fetchExternalImage` follows redirects recursively without re-validating the redirect target against `remotePatterns`

**Root Cause:**

The `validateParams` function correctly validates that the requested image URL matches the configured `remotePatterns` allowlist. However, `fetchExternalImage` uses `fetch(..., { redirect: 'manual' })` and manually follows redirect responses by calling itself recursively with the `Location` header value. This recursive call passes the redirect target URL directly to `fetchExternalImage` without re-running the `remotePatterns` check via `validateParams` or `hasRemoteMatch`.

An attacker who controls any server in `remotePatterns` (or can intercept traffic to it) can redirect the image optimizer to an arbitrary host.

**Attack Scenario:**

A production deployment allows `remotePatterns` for `images.example.com` (legitimate CDN). An attacker sets up a redirect at `https://images.example.com/evil-redirect` that points to `http://internal-metadata-server/latest/meta-data/`. The image optimizer fetches the redirect target and returns its content as an "image," exfiltrating internal service data.

In the audit environment: `remotePatterns` allows `audit-redirect-server:8080`. A request to `/_next/image?url=http://audit-redirect-server:8080/redirect-to-secret&w=640&q=75` causes the optimizer to follow a redirect to `audit-secret-server:9090`, which is not in `remotePatterns`.

**Reproduction Steps:**

```bash
# Negative control — direct access to secret server is blocked (400)
curl -s -o /dev/null -w '%{http_code}' \
  'http://localhost:3000/_next/image?url=http%3A%2F%2Faudit-secret-server%3A9090%2Fsecret-image.jpg&w=640&q=75'
# Expected: 400

# Positive exploit — redirect server in remotePatterns, redirects to secret server
curl -s -o /tmp/exploit.bin -w '%{http_code}' \
  'http://localhost:3000/_next/image?url=http%3A%2F%2Faudit-redirect-server%3A8080%2Fredirect-to-secret&w=640&q=75'
# Expected: 200

# Confirm secret server received the request
docker logs audit-secret-server 2>&1 | grep SECRET_ACCESS
# Expected: SECRET_ACCESS: <timestamp> <ip>
```

**Evidence:**
- Direct request to `audit-secret-server:9090` returns HTTP 400 confirming `remotePatterns` blocks it
- Redirect-mediated request returns HTTP 200 with image data from `audit-secret-server:9090`
- Secret server logs show `SECRET_ACCESS` entry from the Next.js container

**Remediation:**

Re-validate the redirect target against `remotePatterns` before following it. In `fetchExternalImage`, before recursing with the redirect URL, call `hasRemoteMatch(domains, remotePatterns, new URL(redirect))` and throw an `ImageError` if the redirect target is not in the allowlist. This requires threading `domains` and `remotePatterns` through `fetchExternalImage`'s call signature.

Alternatively, use `redirect: 'follow'` in the initial `fetch()` call only after ensuring the final URL matches `remotePatterns` by using a redirect hook or by resolving the full redirect chain before fetching.

---

## VULN-2: Auth Bypass via Internal Header Injection (NEXT_PRIVATE_TEST_HEADERS)

**Severity:** High (requires `NEXT_PRIVATE_TEST_HEADERS` env var to be set in production — a configuration error, not a default-state vulnerability)

**Affected Code:**
- `packages/next/src/server/lib/router-server.ts:230` — conditional skip of `filterInternalHeaders`
- `packages/next/src/server/lib/server-ipc/utils.ts:42-64` — `INTERNAL_HEADERS` list and `filterInternalHeaders` implementation
- `packages/next/src/server/async-storage/request-store.ts:117-143` — `mergeMiddlewareCookies` reads `x-middleware-set-cookie` from request headers

**Root Cause:**

`router-server.ts` calls `filterInternalHeaders(req.headers)` to strip internal Next.js headers from incoming requests before processing. This is the primary security boundary preventing external callers from spoofing internal headers. The bypass:

```typescript
// router-server.ts:230
if (!process.env.NEXT_PRIVATE_TEST_HEADERS) {
  filterInternalHeaders(req.headers)
}
```

When the env var `NEXT_PRIVATE_TEST_HEADERS=1` is set, all internal header filtering is skipped. An external client can then send `x-middleware-set-cookie` with arbitrary cookie values. `mergeMiddlewareCookies` in `request-store.ts` reads this header and merges it into the `cookies()` store, making the attacker-controlled values available to any code that calls `await cookies()`.

**Attack Scenario:**

A developer or CI pipeline accidentally sets `NEXT_PRIVATE_TEST_HEADERS=1` in a production or staging environment. An external attacker sends:

```
x-middleware-set-cookie: session=admin_session_token; Path=/
```

Any server component reading `cookies().get('session')` now sees `admin_session_token`, bypassing session-based authentication entirely.

**Reproduction Steps:**

```bash
# Normal app (port 3000) — header is filtered, shows Access Denied
curl -s \
  -H 'x-middleware-set-cookie: session=admin_session_token; Path=/' \
  'http://localhost:3000/protected'
# Expected: contains "Access Denied"

# Test-headers app (port 3001, NEXT_PRIVATE_TEST_HEADERS=1) — header passes through
curl -s \
  -H 'x-middleware-set-cookie: session=admin_session_token; Path=/' \
  'http://localhost:3001/protected'
# Expected: contains "ADMIN_SECRET_DATA: launch_codes_42"
```

**Evidence:**
- Port 3000 (normal): returns `Access Denied` regardless of injected headers
- Port 3001 (`NEXT_PRIVATE_TEST_HEADERS=1`): returns `ADMIN_SECRET_DATA: launch_codes_42` with injected session cookie

**Remediation:**

`NEXT_PRIVATE_TEST_HEADERS` must never be set in production or staging environments. Its name already signals test-only usage, but the risk should be documented explicitly. Consider:

1. Adding a startup warning when `NEXT_PRIVATE_TEST_HEADERS` is set and `NODE_ENV` is `production`.
2. Restricting the bypass further — e.g., only allow it when also in `NODE_ENV=test` or when a specific CI flag is set.
3. Documenting `NEXT_PRIVATE_TEST_HEADERS` as a security-sensitive variable in the framework's environment variable documentation.

---

## VULN-3: Server Actions Execute Without Origin Header (defense-in-depth gap)

**Severity:** Medium

**Affected Code:**
- `packages/next/src/server/app-render/action-handler.ts:646-651` — explicit allowance for requests without `origin` header
- `packages/next/src/server/app-render/action-handler.ts:1388` — `ACTION_ID_EXPECTED_LENGTH = 42`

**Root Cause:**

The CSRF protection in Server Actions checks the `origin` header against the `host`/`x-forwarded-host` header. When no `origin` header is present, the code logs a warning but allows the action to proceed:

```typescript
// action-handler.ts:646-651
if (!originHost) {
  // This is a handcrafted request without an origin or a request from an unsafe browser.
  // We'll let this through but log a warning.
  // We can't guard against unsafe browsers and handcrafted requests can't contain
  // user credentials that haven't been shared willingly.
  warning = 'Missing `origin` header from a forwarded Server Actions request.'
}
```

This is an explicitly documented design decision. The logic is that handcrafted requests (curl, scripts) cannot obtain user credentials without cooperation; only browser-originated cross-site requests — which always include an `Origin` header — pose real CSRF risk.

**Important caveat:** This behavior is intentional. The comment in the source code accurately describes the threat model. A standard browser-based CSRF attack will always send an `Origin` header, and the check handles that case. This is a defense-in-depth gap rather than an exploitable vulnerability in the traditional sense.

**Residual risk scenario:**

The gap becomes relevant in environments where:
1. A compromised proxy or middleware strips or suppresses `Origin` headers before they reach Next.js, or
2. A victim's credentials (cookies) are somehow already known to an attacker (e.g., via a separate leak), and the attacker wants to invoke server actions on the victim's behalf using a scripted request.

In both cases, the attacker can invoke server actions without triggering CSRF protection, provided they also supply valid session credentials.

**Reproduction Steps:**

```bash
# Extract action ID from built manifest (42 hex chars per ACTION_ID_EXPECTED_LENGTH)
ACTION_ID=$(docker exec audit-nextjs-app \
  cat /app/.next/server/server-reference-manifest.json \
  | grep -oE '[0-9a-f]{42}' | head -1)

# Invoke server action without Origin header
curl -s -X POST \
  -H "Next-Action: $ACTION_ID" \
  -H "Content-Type: text/plain;charset=UTF-8" \
  -H "Cookie: session=victim_session" \
  --data '[]' \
  'http://localhost:3000/'
# Expected: HTTP 200, action executes, response contains session value
```

**Evidence:**
- Action executes and returns HTTP 200 without `origin` header
- Server logs show warning: `Missing 'origin' header from a forwarded Server Actions request`
- With a mismatched `Origin` header, the action is rejected with "Invalid Server Actions request"

**Remediation:**

The current behavior is a deliberate trade-off. Options to improve defense-in-depth:

1. **Require explicit opt-in for missing-origin allowance:** Add a framework config option (e.g., `serverActions.allowMissingOrigin: false`) to reject requests with no `Origin` header in production.
2. **Document the threat model:** Add explicit documentation explaining why missing-origin requests are allowed and under what deployment conditions this becomes a risk (compromised proxies, credential-sharing scenarios).
3. **Add stricter default for production:** Consider rejecting missing-origin requests by default in production mode (`NODE_ENV=production`) and allowing them only in development.

---

## Appendix: Test Environment

```
audit-net (Docker bridge network)
  |
  +-- audit-nextjs-app (3000:3000) — next start, production mode
  +-- audit-nextjs-app-test-headers (3001:3000) — next start, NEXT_PRIVATE_TEST_HEADERS=1
  +-- audit-redirect-server (8080:8080) — issues 302 redirect to secret server
  +-- audit-secret-server (9090:9090) — serves JPEG, logs access
```

To reproduce all findings:
```bash
bash autofyn_audit/setup.sh
bash autofyn_audit/run_all_exploits.sh
bash autofyn_audit/teardown.sh
```
