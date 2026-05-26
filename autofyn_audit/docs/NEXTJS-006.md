# Hardening: Credential Forwarding on App-Configured External Middleware Rewrites

**Severity:** Low-Medium (dangerous default / footgun)
**CWE:** CWE-522: Insufficiently Protected Credentials
**Type:** Defense-in-depth recommendation

### Summary

If application middleware chooses an attacker-controlled external rewrite destination via `NextResponse.rewrite()`, Next.js forwards the original request's `Cookie` and `Authorization` headers to the external target without stripping. This is a missing safety rail on the framework's proxy implementation, not a standalone vulnerability.

### Precondition

The application must have developer-written middleware that rewrites to an attacker-influenced external URL. Next.js has no built-in middleware that does this. The developer must explicitly write code that derives a rewrite destination from user input (e.g., query parameters, path segments, headers).

### Why This Is Still Reportable

Browsers strip the `Authorization` header on cross-origin redirects (per Fetch spec section 4.2). The framework's server-side proxy (`proxyRequest` via `http-proxy`) does not implement equivalent credential protection for cross-origin rewrites. If a developer makes the mistake of rewriting to user-controlled input, the framework amplifies the damage beyond what a browser redirect would allow.

### Why Not a Standalone CVE

The root cause is application middleware code, not the framework. The credential forwarding makes a bad developer mistake worse, but the framework is not introducing the vulnerability — it is failing to mitigate a developer error.

### Recommendation

Strip `Cookie` and `Authorization` headers in `proxyRequest` when the rewrite target is cross-origin (different host from the application). Alternatively, add a `rewrites.allowedExternalHosts` config option.
