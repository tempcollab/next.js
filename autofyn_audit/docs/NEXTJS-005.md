# Hardening: Server Action Origin Check Trusts x-forwarded-host from External Clients

**Severity:** Low
**CWE:** CWE-346: Origin Validation Error
**Type:** Hardening recommendation (not a browser-exploitable vulnerability)

### Summary

The Server Actions CSRF check compares the `Origin` header's host against `x-forwarded-host` (via `parseHostHeader`) without the header being stripped from external requests. Handcrafted requests or deployments that trust client-supplied forwarded headers can satisfy the origin comparison by setting both `Origin` and `x-forwarded-host` to the same attacker-controlled value.

### Browser CSRF Limitation

This is NOT exploitable as browser CSRF. The `Next-Action` header required for Server Action dispatch is a non-simple header that triggers CORS preflight. Next.js returns HTTP 400 for OPTIONS requests on page routes and does not set permissive `Access-Control-Allow-Headers`. Browsers will never send the actual cross-origin POST with custom headers. HTML form submissions cannot set custom headers at all.

### Real-World Exploitability

Limited. Since requests without an `Origin` header are already allowed through by design (line 646-651: "handcrafted requests can't contain user credentials that haven't been shared willingly"), an attacker with stolen credentials can invoke Server Actions via curl without needing this bypass. The `x-forwarded-host` trust issue only matters if a deployment specifically rejects missing-Origin requests (non-default behavior).

### Recommendation

Add `x-forwarded-host` to the `INTERNAL_HEADERS` array, or pass `originDomain` to `parseHostHeader` at line 635 to constrain trusted host values.
