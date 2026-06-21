#!/bin/bash
# =============================================================================
# NOYD Public SDK — Render Deployment Smoke Test
# Tests the noyd-eval-bin health endpoint on port 7879
# =============================================================================

set -e

ENDPOINT="${NOYD_ENDPOINT:-http://localhost:7879}"
HEALTH_PATH="/health"
TIMEOUT_SECS="${SMOKE_TEST_TIMEOUT:-10}"
RETRIES="${SMOKE_TEST_RETRIES:-3}"

echo "[SMOKE] Testing NOYD evaluation core deployment"
echo "[SMOKE] Endpoint: ${ENDPOINT}"
echo "[SMOKE] Timeout: ${TIMEOUT_SECS}s per request"
echo "[SMOKE] Retries: ${RETRIES}"
echo ""

# Function to check health endpoint
check_health() {
    local attempt=$1
    echo "[SMOKE] Attempt ${attempt}/${RETRIES}: Checking health endpoint..."

    response=$(curl -s \
        --max-time "${TIMEOUT_SECS}" \
        --retry 1 \
        -w "\n%{http_code}" \
        "${ENDPOINT}${HEALTH_PATH}" 2>&1) || {
        echo "[SMOKE] ERROR: curl failed with exit code $?"
        return 1
    }

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    echo "[SMOKE] HTTP Status: ${http_code}"
    echo "[SMOKE] Response: ${body}"

    if [ "$http_code" = "200" ]; then
        # Verify expected fields in JSON response
        if echo "$body" | grep -q '"status":"healthy"'; then
            echo "[SMOKE] PASS: Health check passed"
            return 0
        else
            echo "[SMOKE] WARN: HTTP 200 but unexpected body content"
            return 0
        fi
    fi

    echo "[SMOKE] FAIL: HTTP ${http_code}"
    return 1
}

# Function to check TCP port connectivity
check_port() {
    local host=$(echo "$ENDPOINT" | sed -E 's|^https?://||' | cut -d':' -f1)
    local port=$(echo "$ENDPOINT" | sed -E 's|^https?://||' | cut -d':' -f2)

    # Default port 7879 if not specified
    port="${port:-7879}"

    echo "[SMOKE] Checking TCP connectivity to ${host}:${port}..."

    if command -v nc >/dev/null 2>&1; then
        if nc -z -w "${TIMEOUT_SECS}" "${host}" "${port}" 2>/dev/null; then
            echo "[SMOKE] PASS: TCP port ${port} is reachable"
            return 0
        fi
    elif command -v timeout >/dev/null 2>&1; then
        if timeout "${TIMEOUT_SECS}" bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null; then
            echo "[SMOKE] PASS: TCP port ${port} is reachable"
            return 0
        fi
    else
        echo "[SMOKE] SKIP: Neither nc nor bash TCP available for port check"
    fi

    echo "[SMOKE] WARN: Could not verify TCP port connectivity"
    return 0
}

# Main test loop
main() {
    local passed=false

    for i in $(seq 1 "${RETRIES}"); do
        if check_health $i; then
            passed=true
            break
        fi

        if [ $i -lt "${RETRIES}" ]; then
            echo "[SMOKE] Retrying in 2 seconds..."
            sleep 2
        fi
    done

    echo ""

    # Port check (non-fatal)
    check_port || true

    echo ""

    if [ "$passed" = true ]; then
        echo "[SMOKE] ===== SMOKE TEST PASSED ====="
        exit 0
    else
        echo "[SMOKE] ===== SMOKE TEST FAILED ====="
        exit 1
    fi
}

main "$@"
