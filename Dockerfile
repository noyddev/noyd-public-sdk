# =============================================================================
# NOYD Public SDK — Multi-Stage Production Dockerfile
# Stage 1: Builder (golang:1.22-alpine)
# Stage 2: Runner (alpine:latest)
# Optimized for Render.com Free Tier deployment (port 7879)
# =============================================================================


# -----------------------------------------------------------------------------
# Stage 1: Builder
# -----------------------------------------------------------------------------
FROM --platform=linux/amd64 golang:1.22-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache \
    ca-certificates \
    openssl \
    git \
    musl-dev \
    gcc

# Initialize blank go.mod for mock compilation
RUN go mod init noyd-eval && go mod tidy

# Create FFI facade stub (noyd.go replacement)
RUN mkdir -p /build/sdk && cat > /build/sdk/noyd.go << 'EOFFFI'
// noyd.go — NOYD Public SDK Facade (Post-Quantum Mock/Stub)
// This is a standalone evaluation binary for Render.com Free Tier deployment.
// It mocks the ML-KEM-768 / ML-DSA-65 PQC handshake telemetry.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// TelemetryMetric represents a PQC handshake telemetry data point.
type TelemetryMetric struct {
	Timestamp  int64  `json:"timestamp"`
	Protocol   string `json:"protocol"`
	Algorithm  string `json:"algorithm"`
	KeyGenUs   int64  `json:"key_generation_us"`
	EncapUs    int64  `json:"encapsulation_us"`
	DecapUs    int64  `json:"decapsulation_us"`
	SignUs     int64  `json:"signing_us"`
	VerifyUs   int64  `json:"verification_us"`
	SessionID  string `json:"session_id"`
	Status     string `json:"status"`
}

// Session represents a mock NOYD session with PQC state engine.
type Session struct {
	ID        string
	Endpoint  string
	Connected bool
	Metrics   []TelemetryMetric
}

// Connect initiates a mock PQC ML-KEM-768 + ML-DSA-65 handshake.
func Connect(endpoint string) (*Session, error) {
	log.Printf("[NOYD] PQC handshake initiated → endpoint=%s protocol=ML-KEM-768+ML-DSA-65", endpoint)

	// Simulate key generation
	keyGenStart := time.Now()
	time.Sleep(50 * time.Microsecond)
	keyGenUs := time.Since(keyGenStart).Microseconds()

	// Simulate encapsulation
	encapStart := time.Now()
	time.Sleep(30 * time.Microsecond)
	encapUs := time.Since(encapStart).Microseconds()

	// Simulate signing
	signStart := time.Now()
	time.Sleep(20 * time.Microsecond)
	signUs := time.Since(signStart).Microseconds()

	// Emit telemetry
	metric := TelemetryMetric{
		Timestamp: time.Now().UnixMicro(),
		Protocol:  "ML-KEM-768",
		Algorithm: "ML-DSA-65",
		KeyGenUs:  keyGenUs,
		EncapUs:   encapUs,
		DecapUs:   25,
		SignUs:    signUs,
		VerifyUs:  15,
		SessionID: fmt.Sprintf("sess-%d", time.Now().UnixNano()),
		Status:    "ESTABLISHED",
	}

	metricJSON, _ := json.Marshal(metric)
	log.Printf("[NOYD] PQC handshake complete → %s", string(metricJSON))

	return &Session{
		ID:        metric.SessionID,
		Endpoint:  endpoint,
		Connected: true,
		Metrics:   []TelemetryMetric{metric},
	}, nil
}

// HealthHandler exposes the Render health check endpoint.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"service":   "noyd-eval-core",
		"protocol":  "ML-KEM-768+ML-DSA-65",
		"build":     "render-free-tier",
		"timestamp": fmt.Sprintf("%d", time.Now().UnixMicro()),
	})
}

func main() {
	log.Println("[NOYD] noyd-eval-bin v1.0.0 starting on :7879")

	// Open TCP listener for Render health checks
	http.HandleFunc("/health", HealthHandler)

	// Log startup
	log.Printf("[NOYD] Evaluation core state engine initialized")
	log.Printf("[NOYD] ML-KEM-768: enabled")
	log.Printf("[NOYD] ML-DSA-65: enabled")
	log.Printf("[NOYD] Listening on :7879")

	// Perform mock handshake on startup
	session, err := Connect("localhost:7879")
	if err != nil {
		log.Printf("[NOYD] WARNING: mock handshake returned error: %v", err)
	} else {
		log.Printf("[NOYD] Session established: %s", session.ID)
	}

	if err := http.ListenAndServe(":7879", nil); err != nil {
		log.Fatalf("[NOYD] server failed: %v", err)
		os.Exit(1)
	}
}
EOFFFI

# Copy stub and compile binary
RUN mkdir -p /build/cmd/noyd-eval && \
    cp /build/sdk/noyd.go /build/cmd/noyd-eval/main.go && \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /noyd-eval-bin /build/cmd/noyd-eval

# Verify binary
RUN ls -la /noyd-eval-bin && file /noyd-eval-bin


# -----------------------------------------------------------------------------
# Stage 2: Runner
# -----------------------------------------------------------------------------
FROM --platform=linux/amd64 alpine:latest AS runner

# Security: run as non-root
RUN addgroup -g 1000 noyd && adduser -u 1000 -G noyd -s /bin/sh -D noyd

# Install runtime dependencies
RUN apk add --no-cache ca-certificates openssl

WORKDIR /app

# Copy binary from builder
COPY --from=builder /noyd-eval-bin /app/noyd-eval-bin

# Set ownership
RUN chown -R noyd:noyd /app

# Switch to non-root user
USER noyd

# Expose Render health check port
EXPOSE 7879

# Health check for Render
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:7879/health || exit 1

# Execute evaluation binary
CMD ["/app/noyd-eval-bin"]
