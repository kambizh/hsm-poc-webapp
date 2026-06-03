/**
 * PayShield 10K HSM — Sign + Verify Load Test
 * ============================================
 * Tests the connection pool under realistic concurrent signing load.
 *
 * Prerequisites:
 *   1. k6 installed: https://k6.io/docs/get-started/installation/
 *   2. HSM webapp running on Stage with the uat profile:
 *        java -jar hsm-poc-webapp.jar --spring.profiles.active=uat
 *   3. A key pair already generated (or let setup() do it).
 *
 * Run — quick smoke test (3 VUs, 30 s):
 *   k6 run load-tests/k6-sign-verify.js
 *
 * Run — full UAT stress (override VUs / duration):
 *   BASE_URL=http://stage-host:8080 \
 *   POOL_SIZE=10 \
 *   SCENARIO=stress \
 *   k6 run load-tests/k6-sign-verify.js
 *
 * Environment variables:
 *   BASE_URL   - webapp base URL          (default: http://localhost:8080)
 *   POOL_SIZE  - payshield.pool-max-total (default: 10)
 *               Used to compute VU counts for each scenario stage.
 *   SCENARIO   - smoke | ramp | stress | spike (default: smoke)
 *
 * Scenarios:
 *   smoke  — 3 VUs × 30 s.  Sanity check, no stress.
 *   ramp   — ramp from 1 → POOL_SIZE VUs over 2 min, sustain 3 min, ramp down.
 *   stress — ramp to POOL_SIZE × 1.5 (exceed pool) then sustain 5 min + spike.
 *   spike  — instant burst to POOL_SIZE × 3 for 60 s to observe borrow-timeout.
 */

import http from 'k6/http';
import { check, sleep, fail } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ===== Configuration =====

const BASE_URL  = __ENV.BASE_URL  || 'http://localhost:8080';
const POOL_SIZE = parseInt(__ENV.POOL_SIZE || '10');
const SCENARIO  = __ENV.SCENARIO  || 'smoke';

// ===== Custom metrics =====

const mSignDuration    = new Trend('hsm_sign_duration_ms', true);
const mVerifyDuration  = new Trend('hsm_verify_duration_ms', true);
const mCycleDuration   = new Trend('hsm_cycle_duration_ms', true);  // sign + verify combined
const mSignErrorRate   = new Rate('hsm_sign_error_rate');
const mVerifyErrorRate = new Rate('hsm_verify_error_rate');
const mPoolExhausted   = new Counter('hsm_pool_exhausted_count');
const mSigInvalid      = new Counter('hsm_signature_invalid_count');

// ===== Scenario definitions =====

const scenarios = {
  smoke: {
    executor: 'constant-vus',
    vus: 3,
    duration: '30s',
  },

  ramp: {
    executor: 'ramping-vus',
    startVUs: 1,
    stages: [
      { duration: '30s', target: Math.ceil(POOL_SIZE * 0.3) },  // warm up
      { duration: '60s', target: POOL_SIZE },                    // reach pool capacity
      { duration: '3m',  target: POOL_SIZE },                    // sustain at capacity
      { duration: '30s', target: 0 },                            // cool down
    ],
  },

  stress: {
    executor: 'ramping-vus',
    startVUs: 1,
    stages: [
      { duration: '30s', target: Math.ceil(POOL_SIZE * 0.5) },  // gentle ramp
      { duration: '60s', target: POOL_SIZE },                    // pool fully saturated
      { duration: '2m',  target: POOL_SIZE },                    // sustain
      { duration: '30s', target: Math.ceil(POOL_SIZE * 1.5) },  // exceed pool → borrow waits
      { duration: '3m',  target: Math.ceil(POOL_SIZE * 1.5) },  // sustain above pool size
      { duration: '30s', target: POOL_SIZE },                    // back to capacity
      { duration: '1m',  target: POOL_SIZE },                    // cooldown
      { duration: '30s', target: 0 },
    ],
  },

  spike: {
    executor: 'ramping-vus',
    startVUs: 1,
    stages: [
      { duration: '15s', target: 3 },                           // baseline
      { duration: '5s',  target: POOL_SIZE * 3 },               // instant spike → heavy pool exhaustion
      { duration: '60s', target: POOL_SIZE * 3 },               // sustain spike
      { duration: '5s',  target: 3 },                           // drop back
      { duration: '30s', target: 3 },                           // recovery observation
      { duration: '15s', target: 0 },
    ],
  },
};

// ===== Thresholds =====
// Adjust these based on observed HSM baseline from /api/stress/sign-verify.

export const options = {
  scenarios: {
    main: scenarios[SCENARIO],
  },
  thresholds: {
    // Sign: 95th pct must complete within 3 s
    'hsm_sign_duration_ms':   ['p(95)<3000'],
    // Verify (EO + EY): 95th pct within 5 s
    'hsm_verify_duration_ms': ['p(95)<5000'],
    // Combined cycle: 95th pct within 8 s
    'hsm_cycle_duration_ms':  ['p(95)<8000'],
    // Error rate < 1 % for sign and verify
    'hsm_sign_error_rate':    ['rate<0.01'],
    'hsm_verify_error_rate':  ['rate<0.01'],
    // Standard k6 HTTP checks
    'http_req_failed':        ['rate<0.01'],
    'http_req_duration':      ['p(95)<10000'],
  },
};

// ===== Setup — runs once before any VU starts =====

export function setup() {
  console.log(`=== HSM Sign+Verify Load Test ===`);
  console.log(`BASE_URL  : ${BASE_URL}`);
  console.log(`POOL_SIZE : ${POOL_SIZE}`);
  console.log(`SCENARIO  : ${SCENARIO}`);
  console.log(`Generating RSA-2048 key pair (one-time setup)...`);

  const res = http.post(
    `${BASE_URL}/api/generate-keypair`,
    JSON.stringify({ modulusBits: 2048 }),
    { headers: { 'Content-Type': 'application/json' }, timeout: '120s' }
  );

  const ok = check(res, {
    'keygen HTTP 200':  (r) => r.status === 200,
    'keygen success':   (r) => r.json('success') === true,
    'has publicKeyHex': (r) => !!r.json('publicKeyHex'),
  });

  if (!ok) {
    fail(`Key generation failed (status=${res.status}): ${res.body}`);
  }

  const data = {
    publicKeyHex: res.json('publicKeyHex'),
  };

  console.log(`Key pair generated. publicKey length: ${data.publicKeyHex.length} hex chars`);
  console.log(`Pool stats after keygen: ${poolStats()}`);
  return data;
}

// ===== Main VU function — runs once per VU iteration =====

export default function (data) {
  const message = `RPP-PAYMENT-VU${__VU}-ITER${__ITER}-${Date.now()}`;

  const cycleStart = Date.now();

  // --- Sign ---
  const signStart = Date.now();
  const signRes = http.post(
    `${BASE_URL}/api/sign`,
    JSON.stringify({ message, hashId: '06', padMode: '01' }),
    { headers: { 'Content-Type': 'application/json' }, timeout: '30s' }
  );
  const signMs = Date.now() - signStart;

  const signOk = check(signRes, {
    'sign HTTP 200':  (r) => r.status === 200,
    'sign success':   (r) => r.json('success') === true,
    'has signature':  (r) => !!r.json('signatureHex'),
  });

  mSignDuration.add(signMs);
  mSignErrorRate.add(!signOk);

  if (!signOk) {
    if (signRes.status === 500 && (signRes.body || '').includes('pool exhausted')) {
      mPoolExhausted.add(1);
    }
    console.error(`[VU${__VU}] sign failed (${signMs}ms, HTTP ${signRes.status}): ${signRes.body}`);
    return; // skip verify if sign failed
  }

  const signatureHex = signRes.json('signatureHex');

  // --- Verify ---
  const verifyStart = Date.now();
  const verifyRes = http.post(
    `${BASE_URL}/api/verify`,
    JSON.stringify({
      message,
      signatureHex,
      publicKeyHex: data.publicKeyHex,
      hashId: '06',
      padMode: '01',
    }),
    { headers: { 'Content-Type': 'application/json' }, timeout: '30s' }
  );
  const verifyMs = Date.now() - verifyStart;

  const verifyOk = check(verifyRes, {
    'verify HTTP 200': (r) => r.status === 200,
    'verify success':  (r) => r.json('success') === true,
    'signature valid': (r) => r.json('valid') === true,
  });

  mVerifyDuration.add(verifyMs);
  mVerifyErrorRate.add(!verifyOk);

  if (verifyRes.status === 500 && (verifyRes.body || '').includes('pool exhausted')) {
    mPoolExhausted.add(1);
  }
  if (verifyOk && verifyRes.json('valid') === false) {
    mSigInvalid.add(1);
    console.error(`[VU${__VU}] SIGNATURE INVALID (should never happen): ${verifyRes.body}`);
  }

  const cycleMs = Date.now() - cycleStart;
  mCycleDuration.add(cycleMs);

  // Log slow cycles (> 5 s) for investigation
  if (cycleMs > 5000) {
    console.warn(`[VU${__VU}] Slow cycle: ${cycleMs}ms (sign=${signMs}ms, verify=${verifyMs}ms)`);
  }

  // No sleep — maximise throughput pressure on the pool.
  // Uncomment if you want to simulate realistic inter-transaction delay:
  // sleep(0.05);  // 50 ms think time
}

// ===== Teardown — runs once after all VUs finish =====

export function teardown(data) {
  console.log(`=== Teardown ===`);
  console.log(`Final pool stats: ${poolStats()}`);
  console.log(`
  ┌─────────────────────────────────────────────────┐
  │  How to read results                             │
  │                                                  │
  │  hsm_sign_duration_ms p95  ← HSM sign latency   │
  │  hsm_verify_duration_ms p95 ← EO+EY latency     │
  │  hsm_pool_exhausted_count  ← pool saturation     │
  │  hsm_sign_error_rate       ← target < 1%         │
  │                                                  │
  │  If pool_exhausted > 0 and errors > 0:           │
  │    → increase payshield.pool-max-total           │
  │  If p95 > threshold but no errors:               │
  │    → HSM is processing correctly, latency is     │
  │      the HSM response time, not pool overhead    │
  └─────────────────────────────────────────────────┘
  `);
}

// ===== Helper =====

function poolStats() {
  const r = http.get(`${BASE_URL}/api/stress/pool-stats`, { timeout: '5s' });
  if (r.status === 200) {
    try { return r.json('poolStats'); } catch (_) {}
  }
  return '(unavailable)';
}
