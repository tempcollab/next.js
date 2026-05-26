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
echo "[1/6] Creating Docker network..."
docker network create audit-net 2>/dev/null || true

# Build images
echo "[2/6] Building secret server..."
docker build -t audit-secret-server "$SCRIPT_DIR/secret_server/"

echo "[3/6] Building redirect server..."
docker build -t audit-redirect-server "$SCRIPT_DIR/redirect_server/"

echo "[4/6] Building vulnerable Next.js app..."
docker build -t audit-nextjs-app "$SCRIPT_DIR/vulnerable_app/"

# Start containers
echo "[5/6] Starting containers..."
docker run -d --name audit-secret-server --network audit-net -p 9090:9090 audit-secret-server
docker run -d --name audit-redirect-server --network audit-net -p 8080:8080 audit-redirect-server
docker run -d --name audit-nextjs-app --network audit-net -p 3000:3000 audit-nextjs-app
docker run -d --name audit-nextjs-app-test-headers --network audit-net -p 3001:3000 \
  -e NEXT_PRIVATE_TEST_HEADERS=1 audit-nextjs-app

# Health checks — try container DNS names first (in-network), fall back to localhost (host)
echo "[6/6] Waiting for services..."
HEALTH_TARGETS=(
  "audit-secret-server:9090"
  "audit-redirect-server:8080"
  "audit-nextjs-app:3000"
  "audit-nextjs-app-test-headers:3000"
)
LOCALHOST_PORTS=(9090 8080 3000 3001)

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

echo ""
echo "=== Setup complete ==="
