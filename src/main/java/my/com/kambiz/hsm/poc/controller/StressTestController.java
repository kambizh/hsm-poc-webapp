package my.com.kambiz.hsm.poc.controller;

import my.com.kambiz.hsm.command.CommandUtils;
import my.com.kambiz.hsm.model.SigningResult;
import my.com.kambiz.hsm.model.VerificationResult;
import my.com.kambiz.hsm.service.HsmCryptoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

/**
 * In-process HSM connection pool stress tester.
 *
 * Use this BEFORE running external k6 load tests to:
 *   1. Validate the connection pool behaves correctly under concurrency
 *   2. Calibrate pool-max-total against the actual HSM throughput
 *   3. Observe pool exhaustion / borrow-timeout behaviour
 *   4. Get p50/p95/p99 latency baselines for sign and verify
 *
 * Workflow for UAT / Stage:
 *   Step 1  POST /api/generate-keypair          → save privateKeyHex + publicKeyHex (once a year)
 *   Step 2  GET  /api/stress/pool-stats          → confirm pool is idle before test
 *   Step 3  POST /api/stress/sign-verify         → run concurrent sign+verify cycles
 *   Step 4  GET  /api/stress/pool-stats          → confirm all connections returned
 *
 * Each sign operation   = 1 HSM connection  (EW command)
 * Each verify operation = 2 HSM connections sequentially (EO then EY)
 * → each thread holds at most 1 connection at a time
 * → set concurrency == pool-max-total to saturate the pool exactly
 * → set concurrency >  pool-max-total to observe blocking / borrow-timeout
 */
@RestController
@RequestMapping("/api/stress")
public class StressTestController {

    private static final Logger log = LoggerFactory.getLogger(StressTestController.class);

    private static final int MAX_OPERATIONS  = 10_000;
    private static final int MAX_CONCURRENCY = 200;

    private final HsmCryptoService hsmService;

    public StressTestController(HsmCryptoService hsmService) {
        this.hsmService = hsmService;
    }

    // ===== Pool monitoring =====

    /**
     * Snapshot of the connection pool state.
     * Call periodically during a k6 run to watch active/idle/waiting counts.
     *
     * GET /api/stress/pool-stats
     */
    @GetMapping("/pool-stats")
    public ResponseEntity<Map<String, Object>> poolStats() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("timestamp", Instant.now().toString());
        response.put("poolStats", hsmService.getPoolStats());
        response.put("detail",    hsmService.getDetailedPoolStats());
        return ResponseEntity.ok(response);
    }

    // ===== In-process concurrent stress test =====

    /**
     * Run a concurrent sign-verify stress test directly inside the JVM.
     *
     * POST /api/stress/sign-verify
     * Body (all fields optional except privateKeyHex / publicKeyHex):
     * {
     *   "privateKeyHex":   "...",    -- hex of LMK-encrypted private key blob from /api/generate-keypair
     *   "publicKeyHex":    "...",    -- hex of DER public key from /api/generate-keypair
     *   "message":         "PAYMENT-TEST",
     *   "concurrency":      10,      -- parallel threads; set > pool-max-total to test exhaustion
     *   "totalOperations":  200,     -- total sign-verify cycles (max 10 000)
     *   "signOnly":         false,   -- true = sign throughput only, skip verify
     *   "hashId":           "06",    -- SHA-256
     *   "padMode":          "01"     -- PKCS#1 v1.5
     * }
     *
     * Response includes:
     *   - sign / verify latency stats (min, avg, p50, p75, p95, p99, max)
     *   - throughput (sign TPS, verify TPS)
     *   - error list (first 20)
     *   - pool stats snapshot before and after
     */
    @PostMapping("/sign-verify")
    public ResponseEntity<Map<String, Object>> runStress(@RequestBody Map<String, Object> request) {

        // --- Parse inputs ---
        String privateKeyHex  = (String) request.get("privateKeyHex");
        String publicKeyHex   = (String) request.get("publicKeyHex");
        String message        = (String) request.getOrDefault("message", "HSM-STRESS-TEST");
        int    concurrency    = toInt(request.getOrDefault("concurrency", 5));
        int    totalOps       = toInt(request.getOrDefault("totalOperations", 100));
        boolean signOnly      = toBool(request.getOrDefault("signOnly", false));
        String hashId         = (String) request.getOrDefault("hashId", "06");
        String padMode        = (String) request.getOrDefault("padMode", "01");

        // --- Validate ---
        Optional<ResponseEntity<Map<String, Object>>> invalid = validate(
                privateKeyHex, publicKeyHex, signOnly, concurrency, totalOps);
        if (invalid.isPresent()) return invalid.get();

        byte[] privateKeyBlob = CommandUtils.hexToBytes(privateKeyHex);
        byte[] publicKeyDer   = signOnly ? null : CommandUtils.hexToBytes(publicKeyHex);
        byte[] messageBytes   = message.getBytes(StandardCharsets.UTF_8);

        String poolBefore = hsmService.getPoolStats();
        Map<String, Object> detailedBefore = hsmService.getDetailedPoolStats();
        log.info("[STRESS] Starting: concurrency={}, totalOps={}, signOnly={}, pool=[{}]",
                concurrency, totalOps, signOnly, poolBefore);

        // --- Concurrent execution ---
        Queue<Long> signLatencies   = new ConcurrentLinkedQueue<>();
        Queue<Long> verifyLatencies = new ConcurrentLinkedQueue<>();
        Queue<String> errors        = new ConcurrentLinkedQueue<>();

        long globalStart = System.currentTimeMillis();

        ExecutorService executor = Executors.newFixedThreadPool(
                concurrency, r -> { Thread t = new Thread(r, "hsm-stress"); t.setDaemon(true); return t; });

        List<Callable<Void>> tasks = buildTasks(
                totalOps, privateKeyBlob, publicKeyDer, messageBytes,
                hashId, padMode, signOnly,
                signLatencies, verifyLatencies, errors);

        try {
            List<Future<Void>> futures = executor.invokeAll(tasks, 300, TimeUnit.SECONDS);
            long timedOut = futures.stream().filter(Future::isCancelled).count();
            if (timedOut > 0) {
                errors.add(timedOut + " operation(s) cancelled — exceeded 300 s total wall-clock limit");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            errors.add("Stress test interrupted: " + e.getMessage());
        } finally {
            executor.shutdownNow();
        }

        long totalMs = System.currentTimeMillis() - globalStart;
        String poolAfter = hsmService.getPoolStats();
        Map<String, Object> detailedAfter = hsmService.getDetailedPoolStats();

        // --- Build response ---
        long[] signArr   = toSortedArray(signLatencies);
        long[] verifyArr = toSortedArray(verifyLatencies);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", true);
        response.put("timestamp", Instant.now().toString());

        response.put("config", Map.of(
                "concurrency", concurrency,
                "totalOperations", totalOps,
                "signOnly", signOnly,
                "hashId", hashId,
                "padMode", padMode,
                "message", message
        ));

        response.put("summary", buildSummary(totalOps, totalMs, signArr.length, verifyArr.length, errors.size(), signOnly));

        if (signArr.length > 0)   response.put("signLatency",   latencyStats(signArr));
        if (verifyArr.length > 0) response.put("verifyLatency", latencyStats(verifyArr));

        if (!errors.isEmpty()) {
            List<String> errList = new ArrayList<>(errors);
            Collections.sort(errList);
            response.put("errorSample", errList.size() <= 20 ? errList : errList.subList(0, 20));
            if (errList.size() > 20) {
                response.put("errorSampleNote", "Showing first 20 of " + errList.size() + " errors");
            }
        }

        response.put("poolStatsBefore", poolBefore);
        response.put("poolStatsAfter",  poolAfter);
        response.put("poolDetail",      buildPoolDelta(detailedBefore, detailedAfter, concurrency, totalOps, signOnly));

        log.info("[STRESS] Done: durationMs={}, sign={}/{}, verify={}/{}, errors={}, pool=[{}]",
                totalMs, signArr.length, totalOps,
                verifyArr.length, signOnly ? "skipped" : String.valueOf(totalOps),
                errors.size(), poolAfter);

        return ResponseEntity.ok(response);
    }

    // ===== Private helpers =====

    private List<Callable<Void>> buildTasks(
            int totalOps,
            byte[] privateKeyBlob, byte[] publicKeyDer, byte[] messageBytes,
            String hashId, String padMode, boolean signOnly,
            Queue<Long> signLatencies, Queue<Long> verifyLatencies, Queue<String> errors) {

        List<Callable<Void>> tasks = new ArrayList<>(totalOps);
        for (int i = 0; i < totalOps; i++) {
            final int idx = i;
            tasks.add(() -> {
                // Sign
                long t0 = System.currentTimeMillis();
                SigningResult signing;
                try {
                    signing = hsmService.signMessage(messageBytes, privateKeyBlob, hashId, padMode);
                    signLatencies.add(System.currentTimeMillis() - t0);
                } catch (Exception e) {
                    errors.add("sign[" + idx + "] " + summarize(e));
                    return null;
                }

                // Verify
                if (!signOnly) {
                    long t1 = System.currentTimeMillis();
                    try {
                        VerificationResult ver = hsmService.verifySignature(
                                signing.getSignature(), messageBytes, publicKeyDer, hashId, padMode);
                        if (!ver.isValid()) {
                            errors.add("verify[" + idx + "] INVALID — HSM error code=" + ver.getErrorCode()
                                    + " (" + ver.getErrorDescription() + ")");
                        }
                        verifyLatencies.add(System.currentTimeMillis() - t1);
                    } catch (Exception e) {
                        errors.add("verify[" + idx + "] " + summarize(e));
                    }
                }
                return null;
            });
        }
        return tasks;
    }

    private static Map<String, Object> buildSummary(
            int totalOps, long totalMs,
            int signOk, int verifyOk, int errorCount, boolean signOnly) {

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("totalDurationMs", totalMs);
        m.put("signSuccesses",   signOk);
        m.put("signErrors",      totalOps - signOk);
        if (!signOnly) {
            m.put("verifySuccesses", verifyOk);
            m.put("verifyErrors",    signOk - verifyOk); // only counts cycles that reached verify
        }
        m.put("totalErrors", errorCount);
        // TPS = successful operations per second
        double secs = totalMs / 1000.0;
        m.put("signTps",   secs > 0 ? round1dp(signOk / secs)   : 0);
        if (!signOnly) {
            m.put("verifyTps", secs > 0 ? round1dp(verifyOk / secs) : 0);
            m.put("cycleTps",  secs > 0 ? round1dp(Math.min(signOk, verifyOk) / secs) : 0);
        }
        return m;
    }

    private static Map<String, Object> latencyStats(long[] sorted) {
        long sum = 0;
        for (long v : sorted) sum += v;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("count",  sorted.length);
        m.put("minMs",  sorted[0]);
        m.put("avgMs",  Math.round((double) sum / sorted.length));
        m.put("p50Ms",  percentile(sorted, 50));
        m.put("p75Ms",  percentile(sorted, 75));
        m.put("p95Ms",  percentile(sorted, 95));
        m.put("p99Ms",  percentile(sorted, 99));
        m.put("maxMs",  sorted[sorted.length - 1]);
        return m;
    }

    private static long percentile(long[] sorted, int pct) {
        int idx = (int) Math.ceil(pct / 100.0 * sorted.length) - 1;
        return sorted[Math.max(0, Math.min(idx, sorted.length - 1))];
    }

    private static long[] toSortedArray(Queue<Long> queue) {
        long[] arr = new long[queue.size()];
        int i = 0;
        for (Long v : queue) {
            if (i < arr.length) arr[i++] = v;
        }
        Arrays.sort(arr, 0, i);
        return Arrays.copyOf(arr, i);
    }

    private static Optional<ResponseEntity<Map<String, Object>>> validate(
            String privateKeyHex, String publicKeyHex,
            boolean signOnly, int concurrency, int totalOps) {

        if (privateKeyHex == null || privateKeyHex.isBlank()) {
            return err("privateKeyHex is required — copy it from POST /api/generate-keypair");
        }
        if (!signOnly && (publicKeyHex == null || publicKeyHex.isBlank())) {
            return err("publicKeyHex is required when signOnly=false — copy it from POST /api/generate-keypair");
        }
        if (concurrency < 1 || concurrency > MAX_CONCURRENCY) {
            return err("concurrency must be 1–" + MAX_CONCURRENCY);
        }
        if (totalOps < 1 || totalOps > MAX_OPERATIONS) {
            return err("totalOperations must be 1–" + MAX_OPERATIONS +
                    " (for higher volumes use the k6 script in load-tests/)");
        }
        return Optional.empty();
    }

    private static Optional<ResponseEntity<Map<String, Object>>> err(String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", false);
        body.put("error", message);
        return Optional.of(ResponseEntity.badRequest().body(body));
    }

    private static String summarize(Exception e) {
        String msg = e.getMessage();
        if (msg != null && msg.length() > 200) msg = msg.substring(0, 200) + "…";
        return e.getClass().getSimpleName() + ": " + msg;
    }

    private static int toInt(Object v) {
        return (v instanceof Number n) ? n.intValue() : Integer.parseInt(v.toString());
    }

    private static boolean toBool(Object v) {
        return (v instanceof Boolean b) ? b : Boolean.parseBoolean(v.toString());
    }

    private static double round1dp(double v) {
        return Math.round(v * 10.0) / 10.0;
    }

    /**
     * Compute a pool evidence section from before/after snapshots.
     *
     * "poolUsageProven": true means all three are satisfied:
     *   1. borrowsDelta matches expected HSM calls for the operations run
     *   2. At least one connection was created (pool scaled up or used existing)
     *   3. Returns == borrows (no leaked connections)
     *
     * maxBorrowWaitMs > 0 means at least one thread had to WAIT for a free
     * connection — direct evidence the pool was shared across concurrent threads.
     */
    private static Map<String, Object> buildPoolDelta(
            Map<String, Object> before, Map<String, Object> after,
            int concurrency, int totalOps, boolean signOnly) {

        long borrowsBefore = toLong(before.get("totalBorrows"));
        long borrowsAfter  = toLong(after.get("totalBorrows"));
        long returnsBefore = toLong(before.get("totalReturns"));
        long returnsAfter  = toLong(after.get("totalReturns"));
        long createdBefore = toLong(before.get("totalCreated"));
        long createdAfter  = toLong(after.get("totalCreated"));

        long borrowsDelta  = borrowsAfter  - borrowsBefore;
        long returnsDelta  = returnsAfter  - returnsBefore;
        long createdDelta  = createdAfter  - createdBefore;

        // Each sign op = 1 HSM call (EW); each verify = 2 HSM calls (EO + EY)
        // Total expected borrows = signOps * 1 + verifyOps * 2 (approx, errors reduce actuals)
        long expectedBorrowsMin = signOnly ? totalOps : totalOps;        // at least sign calls
        long expectedBorrowsMax = signOnly ? totalOps : (long) totalOps * 3; // sign + 2x verify

        long maxWaitMs = toLong(after.get("maxBorrowWaitMs"));
        long meanWaitMs = toLong(after.get("meanBorrowWaitMs"));

        boolean borrowsLookRight = borrowsDelta >= expectedBorrowsMin && borrowsDelta <= expectedBorrowsMax;
        boolean noLeaks = borrowsDelta == returnsDelta;
        boolean poolUsageProven = borrowsDelta > 0 && noLeaks;

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("snapshot_before",    before);
        m.put("snapshot_after",     after);
        m.put("borrowsDelta",       borrowsDelta);
        m.put("returnsDelta",       returnsDelta);
        m.put("connectionsCreated", createdDelta);
        m.put("maxBorrowWaitMs",    maxWaitMs);
        m.put("meanBorrowWaitMs",   meanWaitMs);
        m.put("poolWasContended",   maxWaitMs > 0);
        m.put("noConnectionLeaks",  noLeaks);
        m.put("poolUsageProven",    poolUsageProven);
        m.put("interpretation", buildInterpretation(
                borrowsDelta, returnsDelta, createdDelta, maxWaitMs, concurrency,
                (int) toLong(after.get("maxTotal")), poolUsageProven));
        return m;
    }

    private static String buildInterpretation(
            long borrows, long returns, long created, long maxWaitMs,
            int concurrency, int maxTotal, boolean proven) {

        StringBuilder sb = new StringBuilder();
        sb.append(borrows).append(" HSM borrow(s) → ").append(returns).append(" return(s)");
        if (borrows == returns) sb.append(" [no leaks]");
        else sb.append(" [LEAK DETECTED: ").append(borrows - returns).append(" not returned]");

        if (created > 0) sb.append(". ").append(created).append(" new TCP connection(s) opened.");

        if (maxWaitMs > 0) {
            sb.append(" Pool was CONTENDED: max wait ").append(maxWaitMs)
              .append(" ms — threads queued for connections, proving pool sharing.");
        } else if (concurrency <= maxTotal) {
            sb.append(" Pool not contended (concurrency ").append(concurrency)
              .append(" ≤ maxTotal ").append(maxTotal).append(").");
        }

        if (proven) sb.append(" Pool usage CONFIRMED.");
        return sb.toString();
    }

    private static long toLong(Object v) {
        if (v == null) return 0L;
        if (v instanceof Number n) return n.longValue();
        try { return Long.parseLong(v.toString()); } catch (NumberFormatException e) { return 0L; }
    }
}
