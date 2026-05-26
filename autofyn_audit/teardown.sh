#!/usr/bin/env bash
echo "=== Teardown ==="
docker rm -f audit-nextjs-app audit-nextjs-app-test-headers audit-redirect-server audit-secret-server audit-nextjs-dev audit-credential-capture audit-middleware-app 2>/dev/null || true
docker network rm audit-net 2>/dev/null || true
echo "=== Teardown complete ==="
