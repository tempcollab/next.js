#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMMIT_HASH="007051470157d38058730ffa0a1983d4b4106424"

echo "=== Next.js Security Audit Setup ==="
echo "Commit: $COMMIT_HASH"
echo ""

# Teardown any previous run
bash "$SCRIPT_DIR/teardown.sh" 2>/dev/null || true

# Create network
echo "[1/9] Creating Docker network..."
docker network create audit-net 2>/dev/null || true

# Build images
echo "[2/9] Building secret server..."
docker build -t audit-secret-server "$SCRIPT_DIR/secret_server/"

echo "[3/9] Building redirect server..."
docker build -t audit-redirect-server "$SCRIPT_DIR/redirect_server/"

echo "[4/9] Building vulnerable Next.js app (production)..."
docker build -t audit-nextjs-app "$SCRIPT_DIR/vulnerable_app/"

echo "[5/9] Building vulnerable Next.js dev app (webpack dev mode)..."
docker build -t audit-nextjs-dev "$SCRIPT_DIR/dev_app/"

echo "[6/9] Building credential capture server..."
docker build -t audit-credential-capture "$SCRIPT_DIR/credential_capture_server/"

echo "[7/9] Building middleware app (production)..."
docker build -t audit-middleware-app "$SCRIPT_DIR/middleware_app/"

# Start containers
echo "[8/9] Starting containers..."
docker run -d --name audit-secret-server --network audit-net -p 9090:9090 audit-secret-server
docker run -d --name audit-redirect-server --network audit-net -p 8080:8080 audit-redirect-server
docker run -d --name audit-nextjs-app --network audit-net -p 3000:3000 audit-nextjs-app
docker run -d --name audit-nextjs-app-test-headers --network audit-net -p 3001:3000 \
  -e NEXT_PRIVATE_TEST_HEADERS=1 audit-nextjs-app
# Dev container: HTTP on 3002, inspector on 9230 (mapped from 9229 inside container)
docker run -d --name audit-nextjs-dev --network audit-net -p 3002:3000 -p 9230:9229 audit-nextjs-dev
docker run -d --name audit-credential-capture --network audit-net -p 9091:9091 audit-credential-capture
docker run -d --name audit-middleware-app --network audit-net -p 3003:3000 audit-middleware-app

# Health checks — try container DNS names first (in-network), fall back to localhost (host)
echo "[9/9] Waiting for services..."
HEALTH_TARGETS=(
  "audit-secret-server:9090"
  "audit-redirect-server:8080"
  "audit-nextjs-app:3000"
  "audit-nextjs-app-test-headers:3000"
  "audit-nextjs-dev:3000"
  "audit-credential-capture:9091"
  "audit-middleware-app:3000"
)
LOCALHOST_PORTS=(9090 8080 3000 3001 3002 9091 3003)

for idx in "${!HEALTH_TARGETS[@]}"; do
  target="${HEALTH_TARGETS[$idx]}"
  fallback="localhost:${LOCALHOST_PORTS[$idx]}"
  echo -n "  Waiting for $target..."
  for i in $(seq 1 90); do
    if curl -s -o /dev/null "http://$target/" 2>/dev/null || curl -s -o /dev/null "http://$fallback/" 2>/dev/null; then
      echo " ready"
      break
    fi
    if [ "$i" -eq 90 ]; then
      echo " TIMEOUT (may still be starting)"
    fi
    sleep 2
  done
done

# Warm up the dev server — first request triggers webpack compilation (30-60s).
# The health check above already does this, but a second request ensures compilation is complete.
echo "  Warming up dev server webpack compilation (may take 30-60s)..."
curl -s -o /dev/null "http://localhost:3002/" 2>/dev/null || true

echo ""
echo "=== Setup complete ==="
