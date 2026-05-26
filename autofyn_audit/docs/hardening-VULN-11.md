# Hardening: x-middleware-prefetch External Injection Causes SSR Short-Circuit

**Severity:** Low-Medium
**CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor / CWE-441: Unintended Proxy or Intermediary
**Type:** Hardening recommendation

### Summary

The internal header `x-middleware-prefetch` is not included in the `INTERNAL_HEADERS` filter list. External clients can inject it to trigger a server-side short-circuit on dynamic pages that skips SSR entirely, returning `{}` with an `x-matched-path` response header that reveals the resolved route pattern.

### Precise Impact

- SSR is skipped: server components, `getServerSideProps`, auth checks, rate limiting, and logging do not execute for the request.
- Route existence is disclosed: the `x-matched-path` response header reveals the resolved pathname (e.g., `/admin/dashboard`), distinguishing existing dynamic routes from 404s.
- Protected content is NOT returned: the response body is always `{}`. No session data, no page content, no server component output is disclosed.

### Why Not "Auth Bypass"

The term "auth bypass" implies the attacker gains access to protected resources. In this case, the auth logic doesn't execute — but neither does any content rendering. The consequence of authentication (protecting content) is not violated because no content is served. The impact is limited to route enumeration (information disclosure) and suppression of server-side effects.

### Recommendation

Add `x-middleware-prefetch` to the `INTERNAL_HEADERS` array in `packages/next/src/server/lib/server-ipc/utils.ts`. This is a one-line fix that prevents external injection while preserving internal prefetch behavior.
