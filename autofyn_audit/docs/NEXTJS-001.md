# SSRF via Image Optimizer Redirect (remotePatterns bypass)

**CVSS3.1:** 7.4 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N`
**CWE:** CWE-918: Server-Side Request Forgery (SSRF)
**Ecosystem:** npm
**Package Name:** next
**Affected Versions:** <= 16.3.0-canary.29
**Patched Versions:** None

> Discovered by [AutoFyn](https://github.com/SignalPilot-Labs/AutoFyn). Full audit: [audit_report.md](https://github.com/tempcollab/next.js/blob/canary/autofyn_audit/audit_report.md)

### Summary

The Next.js image optimizer validates initial image URLs against the configured `remotePatterns` allowlist but does not re-validate redirect targets when following HTTP redirects. An attacker who controls (or can inject a redirect on) any server listed in `remotePatterns` can cause the optimizer to fetch from public hosts not in the allowlist.

### Details

`validateParams` in `image-optimizer.ts:454` checks `hasRemoteMatch` on the initial URL. `fetchExternalImage` at lines 909-928 uses `fetch(..., { redirect: 'manual' })` and recursively follows redirects without re-checking `hasRemoteMatch`. The `isPrivateIp()` check IS enforced on redirect targets, blocking redirects to private IP ranges (RFC 1918, link-local, loopback). However, redirects to arbitrary public/routable hosts bypass the `remotePatterns` allowlist.

```typescript
// image-optimizer.ts:909-928
if (res.status === 301 || res.status === 302 || ...) {
  const redirectUrl = res.headers.get('location')
  // isPrivateIp enforced, but hasRemoteMatch is NOT called
  return fetchExternalImage(redirectUrl, dangerouslyAllowLocalIP, maximumResponseBody, count + 1)
}
```

The CVSS is scored conservatively at 7.4 rather than higher because `isPrivateIp` prevents access to cloud metadata endpoints (169.254.169.254) and internal network services in default configuration. The bypass is limited to reaching public hosts not in the configured allowlist.

### PoC

```bash
# Direct access to unauthorized server — blocked (400):
curl -s -o /dev/null -w '%{http_code}' \
  'http://localhost:3000/_next/image?url=http%3A%2F%2Faudit-secret-server%3A9090%2Fsecret-image.jpg&w=640&q=75'

# Redirect from allowed server bypasses remotePatterns — succeeds (200):
curl -s -o /dev/null -w '%{http_code}' \
  'http://localhost:3000/_next/image?url=http%3A%2F%2Faudit-redirect-server%3A8080%2Fredirect-to-secret&w=640&q=75'
```

Note: The Docker PoC uses `dangerouslyAllowLocalIP: true` because the test network uses private IPs. Without this flag, `isPrivateIp()` blocks redirects to private ranges. The core bypass works against public hosts without this flag.

### Impact

An attacker can use any allowed CDN/image host as a redirect trampoline to reach public endpoints not in `remotePatterns`. This bypasses the allowlist but not the private IP protection. Impact depends on what attacker-controlled public endpoints can do with the request (e.g., logging the request, returning crafted image data).
