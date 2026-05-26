# Edge Runtime Server Action Unbounded Body (DoS)

**CVSS3.1:** 5.3 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`
**CWE:** CWE-770: Allocation of Resources Without Limits or Throttling
**Ecosystem:** npm
**Package Name:** next
**Affected Versions:** Confirmed on 16.3.0-canary.29 (commit `007051470157d38058730ffa0a1983d4b4106424`); earlier versions not exhaustively tested
**Patched Versions:** None

> Discovered by [AutoFyn](https://github.com/SignalPilot-Labs/AutoFyn). Full audit: [audit_report.md](https://github.com/tempcollab/next.js/blob/canary/autofyn_audit/audit_report.md)

### Summary

The Node runtime path for Server Actions enforces a configurable body size limit (default 1MB) via `sizeLimitTransform`. The edge runtime path has an explicit `// TODO: add body limit` comment and no enforcement — both `formData()` and the streaming reader loop buffer the entire request body without size checks.

### Details

In `action-handler.ts`, the Node runtime path (line 901-931) wraps the request body in `sizeLimitTransform` which counts bytes and throws `ApiError(413)` when the limit is exceeded. The edge runtime path (lines 749-869) has no equivalent check:

- Line 759: `// TODO: add body limit`
- Line 773: `await req.request.formData()` — reads entire multipart body unbounded
- Lines 851-862: `while(true)` reader loop — accumulates non-multipart body unbounded

The `serverActions.bodySizeLimit` configuration value is available at this point but is not used in the edge path.

### PoC

```bash
# Generate 2MB payload:
dd if=/dev/zero bs=1024 count=2048 | tr '\0' 'A' > /tmp/2mb_payload

# Node runtime — rejects (logs "Body exceeded 1 MB limit"):
curl -s -X POST -H "Next-Action: $ACTION_ID_NODE" \
  -H "Content-Type: text/plain;charset=UTF-8" \
  --data-binary @/tmp/2mb_payload "http://localhost:3000/"

# Edge runtime — accepts (no limit, fully buffered):
curl -s -X POST -H "Next-Action: $ACTION_ID_EDGE" \
  -H "Content-Type: text/plain;charset=UTF-8" \
  --data-binary @/tmp/2mb_payload "http://localhost:3004/"
```

### Impact

On self-hosted edge deployments (not behind Vercel/Cloudflare platform limits), an attacker can send arbitrarily large request bodies to edge-runtime Server Action endpoints, causing memory pressure. Managed platforms (Vercel Edge Functions, Cloudflare Workers) enforce their own body size limits at the infrastructure layer, reducing practical impact for those deployments.
