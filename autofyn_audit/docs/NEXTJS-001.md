# SSRF via Image Optimizer Redirect (remotePatterns bypass)

**CVSS3.1:** 7.4 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N`
**CWE:** CWE-918: Server-Side Request Forgery (SSRF)
**Ecosystem:** npm
**Package Name:** next
**Affected Versions:** <= 16.3.0-canary.29
**Patched Versions:** None

> Discovered by [AutoFyn](https://github.com/SignalPilot-Labs/AutoFyn). Full audit: [audit_report.md](https://github.com/tempcollab/next.js/blob/canary/autofyn_audit/audit_report.md)

### Summary

The Next.js image optimizer validates requested image URLs against `remotePatterns` but does not re-validate redirect targets. An attacker who can place a redirect on any host in `remotePatterns` (open redirect, compromised CDN path, or controlled subdomain) can serve attacker-controlled image content through the victim application's `/_next/image` endpoint. The optimized result is cached to disk and served to all subsequent visitors, enabling image cache poisoning from the application's own domain.

### Details

`validateParams` in `image-optimizer.ts:454` calls `hasRemoteMatch` on the initial URL. `fetchExternalImage` at lines 909-928 follows redirects recursively by calling itself with the `Location` header value. The recursive call does not invoke `hasRemoteMatch` — only `isPrivateIp()` is checked (blocking private/loopback ranges).

```typescript
// image-optimizer.ts:909-928
if (res.status === 301 || res.status === 302 || ...) {
  const redirectUrl = res.headers.get('location')
  // isPrivateIp blocks private ranges, but hasRemoteMatch is NOT re-checked
  return fetchExternalImage(redirectUrl, dangerouslyAllowLocalIP, maximumResponseBody, count + 1)
}
```

After fetching, the image is processed and written to the disk LRU cache via `writeToCacheDir` (line 723). Subsequent requests for the same URL parameters receive the cached result without re-fetching. This means a single poisoned redirect serves the attacker's image to all visitors until cache expiry.

The attack does NOT require `dangerouslyAllowLocalIP` — it works against any public redirect target. The `isPrivateIp` check prevents reaching internal/cloud metadata endpoints, but does not prevent fetching from attacker-controlled public servers.

### PoC

```bash
# Direct access to unauthorized server — blocked (400):
curl -s -o /dev/null -w '%{http_code}' \
  'http://localhost:3000/_next/image?url=http%3A%2F%2Faudit-secret-server%3A9090%2Fsecret-image.jpg&w=640&q=75'

# Redirect from allowed server bypasses remotePatterns — succeeds (200):
curl -s -o /dev/null -w '%{http_code}' \
  'http://localhost:3000/_next/image?url=http%3A%2F%2Faudit-redirect-server%3A8080%2Fredirect-to-secret&w=640&q=75'

# Confirm target server was reached (remotePatterns bypassed):
docker logs audit-secret-server 2>&1 | grep SECRET_ACCESS
```

Note: Docker PoC uses `dangerouslyAllowLocalIP: true` because the test network uses private IPs. The core vulnerability (redirect to public hosts not in `remotePatterns`) works without this flag.

### Impact

An attacker can serve arbitrary image content from the victim application's domain (`yoursite.com/_next/image?...`). The poisoned image is cached and served to all visitors. Realistic attack scenarios:

- **Phishing:** Display fake "account locked" or "verify identity" messages as images on legitimate pages
- **Defacement:** Replace product/brand images with offensive or competitor content
- **Credential harvesting:** Show fake login form screenshots that appear to come from the trusted domain
- **SEO/ad injection:** Inject advertisement or spam images into cached pages

The attack requires a redirect on any host in the application's `remotePatterns` config — open redirects on CDNs are common (e.g., via query parameter redirect endpoints, compromised image paths, or attacker-controlled subdomains on wildcard patterns).
