# Dev Server DNS Rebinding Bypass Exposes Internal Endpoints

**CVSS3.1:** 6.3 `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N`
**CWE:** CWE-350: Reliance on Reverse DNS Resolution for a Security-Critical Action
**Ecosystem:** npm
**Package Name:** next
**Affected Versions:** <= 16.3.0-canary.29
**Patched Versions:** None

> Discovered by [AutoFyn](https://github.com/SignalPilot-Labs/AutoFyn). Full audit: [audit_report.md](https://github.com/tempcollab/next.js/blob/canary/autofyn_audit/audit_report.md)

### Summary

The `blockCrossSiteDEV` function in the Next.js dev server allows all requests with no `Origin` header and never validates the `Host` header. Under DNS rebinding, a malicious webpage can reach all `/__nextjs*` dev endpoints by exploiting this gap in Firefox and Safari. Chrome's Private Network Access (PNA) blocks this attack vector.

The exposed endpoints include:
- `/__nextjs_source-map` — file existence oracle (204 vs 500) and source-map content disclosure when the target file contains or references a readable source map with `sourcesContent`; error responses leak absolute paths
- `/__nextjs_launch-editor` — file existence oracle via path traversal (204/404 differential)

### Details

`blockCrossSiteDEV` in `block-cross-site-dev.ts:169-174`:

```typescript
return (
  originLowerCase !== undefined &&
  !isCsrfOriginAllowed(originLowerCase, allowedOrigins) &&
  blockRequest(req, res, originLowerCase)
)
```

When `originLowerCase === undefined` (no Origin header), the expression short-circuits to `false` — the request is allowed. The `Host` header is never checked. This is DNS rebinding-compatible server behavior: under DNS rebinding, the browser sends same-origin requests (no Origin header) with the attacker's Host value. The curl PoC below demonstrates the server-side bypass condition; a full browser DNS rebinding PoC requires external DNS infrastructure with short TTL.

**Source map endpoint (independently exploitable):** `/__nextjs_source-map` accepts a `filename` parameter with no path validation. `getSourceMapFromFile` reads the file, then searches for a `//# sourceMappingURL=` comment. If found, it reads and returns the referenced source map (parsed as JSON with `sourcesContent`). If no `sourceMappingURL` is present, the endpoint returns 204 (file exists) without disclosing contents. If the file does not exist, the endpoint returns 500 with error details including the absolute path. This creates a file existence oracle (204 vs 500), source map disclosure for files that already reference source maps, and path leakage in error responses.

**Launch-editor path traversal (independently exploitable):** `/__nextjs_launch-editor` with `isAppRelativePath=1` allows `../` sequences in `path.join`, resolving to paths outside the project root. `fsp.access(filePath, F_OK)` returns 204/404 based on file existence.

### PoC

```bash
# DNS rebinding bypass:
curl -s -o /dev/null -w '%{http_code}' -H "Host: evil.com:3000" \
  "http://localhost:3002/__nextjs_source-map?filename=test"
# Returns non-403 (bypassed)

# Source map file read:
curl -s 'http://localhost:3002/__nextjs_source-map?filename=/tmp/chain.js'
# Returns secret from sourceMappingURL target

# Path traversal oracle:
curl -s -o /dev/null -w '%{http_code}' \
  'http://localhost:3002/__nextjs_launch-editor?file=../../../../etc/passwd&isAppRelativePath=1'
# Returns 204 (file exists)
```

### Impact

The dev server's `blockCrossSiteDEV` does not validate the `Host` header, making it compatible with DNS rebinding attacks in Firefox and Safari (Chrome blocks via Private Network Access). An attacker can enumerate file existence on the developer's machine (via 204/500 differential on source-map endpoint and 204/404 on launch-editor), read source map contents for project files that reference source maps, and leak absolute paths from error responses. The endpoints are also directly exploitable by any process with network access to the dev server port (CI environments, cloud IDEs, adjacent network devices).
