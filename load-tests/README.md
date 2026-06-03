# HSM Connection Pool — Load Test Guide

This directory contains the k6 load test for the PayShield 10K signing and verification flow.
It is designed to validate the connection pool introduced in `payshield-crypto-client` under
realistic concurrent load on the **Stage / UAT** environment.

---

## Why a load test here?

The production use case for RPP message signing is:

| Operation | Frequency |
|-----------|-----------|
| RSA key-pair generation | **Once a year** (annual renewal) |
| Message signing (EW) | **Millions of times** — the hot path |
| Signature verification (EO + EY) | **Millions of times** — the hot path |

The connection pool (`PayShieldConnectionPool`) allows multiple threads to sign and verify
concurrently — one TCP connection per thread, up to `payshield.pool-max-total`. These tests
verify that the pool behaves correctly under that concurrent pressure.

---

## Tools

| Tool | Purpose |
|------|---------|
| `POST /api/stress/sign-verify` | **In-process** stress test — no extra tooling required |
| `GET  /api/stress/pool-stats`  | Live pool snapshot (active / idle / waiting) |
| `k6-sign-verify.js`            | **External** k6 load test — realistic HTTP client simulation |

Use the **in-process endpoint first** (Step 2–4 below) to calibrate the pool without any
external tooling. Then use **k6** for the full UAT sign-off.

---

## Prerequisites

### Application

```bash
# Build crypto-client (if not already installed)
cd ../payshield-crypto-client
mvn install -DskipTests

# Run webapp with the UAT profile
cd ../hsm-poc-webapp
mvn spring-boot:run -Dspring-boot.run.profiles=uat
# or, from jar:
java -Dspring.profiles.active=uat -jar target/hsm-poc-webapp-*.jar
```

The `uat` profile (`application-uat.properties`) sets:

```properties
payshield.pool-max-total=10
payshield.pool-borrow-timeout-ms=8000
logging.level.my.com.kambiz.hsm=INFO   # quieter under load
```

### k6 (for the external test only)

```bash
# macOS
brew install k6

# Linux (Debian/Ubuntu)
sudo gpg -k
sudo gpg --no-default-keyring \
  --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
  --keyserver hkp://keyserver.ubuntu.com:80 \
  --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] \
  https://dl.k6.io/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update && sudo apt-get install k6

# Verify
k6 version
```

---

## Recommended test sequence

### Step 1 — Generate the key pair (once a year in production)

```bash
curl -s -X POST http://localhost:8080/api/generate-keypair \
  -H 'Content-Type: application/json' \
  -d '{"modulusBits": 2048}' | jq '{publicKeyHex, privateKeyHex: .privateKeyHex}'
```

> Save `publicKeyHex` and the **full** (un-truncated) private key blob.
> The webapp keeps the key pair in memory for the session; subsequent
> `/api/sign` calls use it automatically.
> For the in-process stress endpoint you supply both values directly.

---

### Step 2 — Baseline: single-threaded sign-only

Establishes raw HSM sign latency with **zero pool contention**.

```bash
curl -s -X POST http://localhost:8080/api/stress/sign-verify \
  -H 'Content-Type: application/json' \
  -d '{
    "privateKeyHex":   "<paste privateKeyHex here>",
    "publicKeyHex":    "<paste publicKeyHex here>",
    "message":         "RPP-BASELINE-001",
    "concurrency":      1,
    "totalOperations":  20,
    "signOnly":         true
  }' | jq '.signLatency'
```

**Expected output:**

```json
{
  "count": 20,
  "minMs": 140,
  "avgMs": 160,
  "p50Ms": 158,
  "p75Ms": 165,
  "p95Ms": 185,
  "p99Ms": 200,
  "maxMs": 210
}
```

Note the `p95Ms` value — this is your HSM baseline. All subsequent pool tests will show
higher values under contention; the delta is queuing overhead.

---

### Step 3 — Saturate the pool (concurrency == pool-max-total)

All 10 connections are used simultaneously. No thread should ever wait.

```bash
curl -s -X POST http://localhost:8080/api/stress/sign-verify \
  -H 'Content-Type: application/json' \
  -d '{
    "privateKeyHex":   "<paste>",
    "publicKeyHex":    "<paste>",
    "message":         "RPP-SATURATE",
    "concurrency":      10,
    "totalOperations":  300,
    "signOnly":         false
  }' | jq '{summary, signLatency, verifyLatency, poolStatsBefore, poolStatsAfter}'
```

**Pass criteria:**
- `summary.signErrors == 0`, `summary.verifyErrors == 0`
- `summary.signTps` is approximately `10 × step-2-single-thread-TPS`
- `poolStatsAfter` shows `active=0, waiting=0`

---

### Step 4 — Exceed the pool (concurrency > pool-max-total)

15 threads compete for 10 connections. 5 threads must wait up to `pool-borrow-timeout-ms` (8 s).

```bash
curl -s -X POST http://localhost:8080/api/stress/sign-verify \
  -H 'Content-Type: application/json' \
  -d '{
    "privateKeyHex":   "<paste>",
    "publicKeyHex":    "<paste>",
    "message":         "RPP-EXCEED-POOL",
    "concurrency":      15,
    "totalOperations":  300,
    "signOnly":         false
  }' | jq '{summary, signLatency, errors: .errorSample}'
```

**Interpreting results:**

| Observation | Meaning | Action |
|-------------|---------|--------|
| `errors = 0`, `p95Ms` slightly higher | Threads waited, but within `borrow-timeout-ms` | Pool + timeout configured correctly |
| `errors > 0` containing "pool exhausted" | `borrow-timeout-ms` too short for burst duration | Increase `pool-borrow-timeout-ms` or `pool-max-total` |
| `errors > 0` containing "communication error" | Broken connection was invalidated and destroyed | Expected and safe; pool created a fresh one |

---

### Step 5 — Sustained external load with k6

Use k6 to simulate realistic HTTP clients hitting the webapp from outside.
k6 calls the individual `/api/sign` and `/api/verify` endpoints — the key pair
generated in Step 1 must still be in the app's memory (or restart the app and
re-run Step 1).

```bash
# Smoke test — 3 VUs × 30 s (sanity)
BASE_URL=http://localhost:8080 POOL_SIZE=10 SCENARIO=smoke \
  k6 run load-tests/k6-sign-verify.js

# Ramp test — 1 → 10 VUs, sustain 3 min
BASE_URL=http://stage-host:8080 POOL_SIZE=10 SCENARIO=ramp \
  k6 run load-tests/k6-sign-verify.js

# Stress test — exceed pool by 1.5× then sustain 5 min
BASE_URL=http://stage-host:8080 POOL_SIZE=10 SCENARIO=stress \
  k6 run load-tests/k6-sign-verify.js

# Spike test — instant 3× burst
BASE_URL=http://stage-host:8080 POOL_SIZE=10 SCENARIO=spike \
  k6 run load-tests/k6-sign-verify.js
```

**Key k6 metrics to watch:**

| Metric | Threshold | Meaning |
|--------|-----------|---------|
| `hsm_sign_duration_ms` p95 | < 3 000 ms | HSM sign latency |
| `hsm_verify_duration_ms` p95 | < 5 000 ms | EO + EY round-trip |
| `hsm_cycle_duration_ms` p95 | < 8 000 ms | Full sign + verify |
| `hsm_sign_error_rate` | < 1 % | Unexpected sign failures |
| `hsm_verify_error_rate` | < 1 % | Unexpected verify failures |
| `hsm_pool_exhausted_count` | 0 | Pool correctly sized |

---

## Pool sizing guide

Each HSM operation borrows **one connection** at a time:

| Operation | Connections used | Notes |
|-----------|-----------------|-------|
| Sign (EW) | 1 (borrow → return) | Single HSM command |
| Verify (EO then EY) | 1 per command, sequential | EO returned before EY borrows |
| Sign + Verify cycle | Max 1 at any moment | No parallel connection holding |

Therefore: **`pool-max-total` = the number of concurrent signing threads you want to support**.

```
Starting recommendation:
  Stage / UAT:   pool-max-total = 10,  borrow-timeout = 8 000 ms
  Production:    pool-max-total = 20+, borrow-timeout = 5 000 ms (fail fast)
```

Increase `pool-max-total` until `hsm_pool_exhausted_count = 0` and p95 latency is stable.
Each additional connection consumes a TCP socket and a slot on the HSM's licensed
connection limit — check the payShield licence capacity before setting very high values.

---

## Monitoring during a test

Poll the live pool state from a second terminal while k6 runs:

```bash
watch -n 1 'curl -s http://localhost:8080/api/stress/pool-stats | jq .poolStats'
```

Expected output during sustained load at full pool:

```
"active=10, idle=0, waiting=0, maxTotal=10"
```

During pool-exceeding phases you will see `waiting > 0` — that is normal and expected.
If `waiting` persists long after the load drops, check for connection leaks
(broken connections not being invalidated).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `pool exhausted` errors | `pool-max-total` too low or `borrow-timeout-ms` too short | Increase one or both |
| `Short read from HSM` | HSM closed the connection (idle timeout) | Reduce `minEvictableIdleDuration` in pool config |
| `HSM communication error` | TCP connection dropped | Normal — pool invalidates and recreates; check HSM logs |
| `verifyErrors > 0`, code `01` | Key block MAC mismatch | LMK mode mismatch between sign and verify |
| `signatureInvalid` in k6 | Key pair in memory was overwritten | Restart app, re-run Step 1, then k6 |
| p95 latency > threshold | HSM processing time, not pool | Reduce message size or check HSM load |
