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
- `/__nextjs_source-map` — arbitrary file read via `filename` parameter (no path validation)
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

When `originLowerCase === undefined` (no Origin header), the expression short-circuits to `false` — the request is allowed. DNS-rebound requests are same-origin from the browser's perspective, so no Origin header is sent. The `Host` header is never checked.

**Source map file read (independently exploitable):** `/__nextjs_source-map` accepts a `filename` parameter with no validation. `getSourceMapFromFile` reads the file at the given path, then follows any `//# sourceMappingURL=` comment to read a second file. This allows reading arbitrary filesystem contents accessible to the Node process.

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

A developer running `next dev` who visits a malicious webpage in Firefox or Safari exposes their local filesystem to the attacker's page. The attacker can read arbitrary files (via source-map chaining) and enumerate filesystem paths (via launch-editor oracle). Chrome users are protected by Private Network Access. The endpoints are also directly exploitable by any process with network access to the dev server port (CI environments, cloud IDEs, adjacent network devices).
