# NOYD Network SDK
### Post-Quantum Sovereign Transport Layer

[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8.svg)](https://go.dev)
[![Rust](https://img.shields.io/badge/Rust-1.80+-DEA584.svg)](https://www.rust-lang.org)

---

## What is NOYD?

NOYD is a **high-performance post-quantum secure transport layer** for sovereign enterprise infrastructure. It provides cryptographic protection against both classical and quantum adversaries using NIST-standardized lattice-based primitives (ML-KEM-768 + ML-DSA-65).

**The open-core model:** The interface layers, SDK facades, deployment manifests, and the mathematical security framework are fully open-source. The **cryptographic core engine** ships as a pre-compiled, cryptographically signed binary — delivering maximum security without exposing implementation details.

---

## Open-Core Architecture

```
Application Layer
  ├── Go:  noyd.Connect(addr) → client.Send/Receive
  └── Rust: noyd::connect(addr) → session.send/recv
         │  Standard SDK call (no crypto visible)
         ▼
  NOYD SDK Interface (OPEN-SOURCE)
  ├── go-sdk/noyd.go       — Clean Go facade
  ├── rust-sdk/src/facade.rs — Clean Rust async facade
  └── k8s/                 — Kubernetes deployment manifests
         │  FFI / cgo (pre-linked binary)
         ▼
  NOYD Core Engine (PROPRIETARY — pre-compiled binary)
  ├── libnoyd_core.so / .a / .dylib
  ├── ML-KEM-768 key exchange
  ├── ML-DSA-65 authentication
  ├── Fertik self-healing state machine
  └── 64KB deterministic wire protocol
```

---

## Quick Start

### Go

```go
package main

import (
    "log"
    noyd "github.com/noyddev/Noydmvp/go-sdk"
)

func main() {
    client, err := noyd.Connect("localhost:7878")
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    if err := client.Send([]byte("hello post-quantum world")); err != nil {
        log.Fatal(err)
    }

    reply, err := client.Receive()
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("reply: %s", string(reply))
}
```

**Build:**
```bash
# Requires the NOYD Core evaluation binary (see "Getting the Core" below)
go build -ldflags="-linkmode=external -extldflags=-static" ./cmd/client
```

### Rust

```rust
use noyd::connect;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = connect("localhost:7878").await?;

    session.send(b"hello post-quantum world").await?;
    let reply = session.recv().await?;
    session.close().await?;

    println!("reply: {}", String::from_utf8_lossy(&reply));
    Ok(())
}
```

**Build:**
```bash
# Requires the NOYD Core .rlib (see "Getting the Core" below)
cargo build --release
```

---

## Getting the Core Binary

The cryptographic engine ships as a pre-compiled, signed binary.

### Option 1: Evaluation Build (Free Tier)

Download the signed evaluation build from the NOYD developer portal:

```bash
mkdir -p go-sdk/libs
curl -L https://noyd.dev/eval/libnoyd_core.so \
    -o go-sdk/libs/libnoyd_core.so
```

The evaluation build is rate-limited and intended for development/testing purposes only.
Sign up at [noyd.dev](https://noyd.dev) for access credentials.

### Option 2: Enterprise Build

Enterprise customers receive a cryptographically signed production binary through
their authorized distribution channel. Contact your NOYD account team.

---

## Deployment

Deploy the NOYD daemon to a Kubernetes cluster with Calico, Cilium, or Weave
(CNI plugin required for NetworkPolicy enforcement).

```bash
# Create the isolated namespace and deploy
kubectl apply -f k8s/daemon-statefulset.yaml
kubectl apply -f k8s/network-policy.yaml

# Verify the StatefulSet is healthy
kubectl get pods -n noyd-system
kubectl rollout status statefulset/noyd-node -n noyd-system

# Watch the Fertik liveness probes
kubectl get pods -n noyd-system -w

# Check node logs
kubectl logs -n noyd-system -l app.kubernetes.io/name=noyd --tail=100
```

**Prerequisites:**
- Kubernetes 1.28+
- CNI plugin with NetworkPolicy support
- `kubectl` configured with cluster access

---

## Stress-Testing the Telemetry Endpoints

Once deployed, validate the system's self-healing behaviour using the included test scripts.

### Prerequisites

```bash
# Enable metrics-server for kubectl top pods
kubectl apply -f k8s/metrics-server.yaml   # or your cloud provider addon
```

### Run the Reboot Loop Stress Test

```bash
# Inject failures and verify container restarts (3 cycles)
./scripts/test-reboot-loop.sh 0 3

# Expected: Container restarted within MAX_WAIT=60s, Fertik transitions to Failed
```

### Run the Telemetry Profiler

```bash
# Poll CPU/memory every 5s for 5 minutes
./scripts/profile-telemetry.sh --duration 300 --interval 5

# Or alongside the reboot loop
./scripts/profile-telemetry.sh --stress-test ./scripts/test-reboot-loop.sh 0 3

# Outputs:
#   logs/telemetry.csv        — structured metrics (CPU, memory, deltas)
#   logs/telemetry.log        — annotated samples
#   logs/telemetry_alerts.log — breach events (>512Mi, >500m CPU, leak suspect)
```

---

## Security Model

The NOYD transport layer provides the following guarantees, formally specified in `docs/WHITEPAPER.md`:

| Property | Mechanism |
|----------|-----------|
| Post-quantum key exchange | ML-KEM-768 (NIST FIPS 203) — Module-LWE, Level 3 |
| Post-quantum authentication | ML-DSA-65 (NIST FIPS 204) — Module-Lattice, Level 3 |
| Memory sanitization | Triple-pass zeroization on all key material |
| Frame integrity | Hard 64KB envelope, constant-time length verification |
| Self-healing | Fertik deterministic state machine, 1500ms timeout discipline |

The cryptographic security proof sketch, Fertik state machine specification, and
performance benchmarks are available in `docs/WHITEPAPER.md`.

---

## Open-Source Components

The following components are fully open-source under the LICENSE file:

| Component | Path |
|-----------|------|
| Go SDK public facade | `go-sdk/noyd.go` |
| Go SDK error types | `go-sdk/errors.go` |
| Rust SDK public facade | `rust-sdk/src/facade.rs` |
| Rust SDK public interface | `rust-sdk/src/lib.rs` |
| Kubernetes manifests | `k8s/*.yaml` |
| Fertik stress-test | `scripts/test-reboot-loop.sh` |
| Telemetry profiler | `scripts/profile-telemetry.sh` |

**Proprietary components** (NOT in this repository):
- ML-KEM-768 and ML-DSA-65 cryptographic implementations
- The wire protocol codec (NoydWireCodec)
- The NoydClient handshake and session management logic
- All internal error handling and state machine implementations

---

## License

This repository contains open-source interface components. The NOYD Core binary
engine is proprietary software. See the [LICENSE](LICENSE) file for details.

**NOYD Core v1.0 — All Rights Reserved.**
