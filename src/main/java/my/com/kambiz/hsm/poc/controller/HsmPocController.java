package my.com.kambiz.hsm.poc.controller;

import my.com.kambiz.hsm.command.CommandUtils;
import my.com.kambiz.hsm.config.LmkMode;
import my.com.kambiz.hsm.exception.PayShieldException;
import my.com.kambiz.hsm.model.*;
import my.com.kambiz.hsm.service.HsmCryptoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import my.com.kambiz.hsm.command.DiagnosticCommands;

/**
 * Web controller for the payShield 10K HSM POC.
 * Provides REST endpoints for key generation, signing, and verification.
 */
@Controller
public class HsmPocController {

    private static final Logger log = LoggerFactory.getLogger(HsmPocController.class);

    private final HsmCryptoService hsmService;

    // In-memory state for the POC session
    private KeyGenerationResult lastKeyPair;
    private SigningResult lastSignature;
    private String lastSignedMessage;

    public HsmPocController(HsmCryptoService hsmService) {
        this.hsmService = hsmService;
    }

    /** Serve the main UI page */
    @GetMapping("/")
    public String index() {
        return "index";
    }

    // ===== REST API =====

    /**
     * Generate RSA key pair via HSM.
     * POST /api/generate-keypair
     * Body: { "modulusBits": 2048 }
     */
    @PostMapping("/api/generate-keypair")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> generateKeyPair(@RequestBody Map<String, Object> request) {
        Map<String, Object> response = new LinkedHashMap<>();
        long start = System.currentTimeMillis();

        try {
            int modulusBits = (int) request.getOrDefault("modulusBits", 2048);
            LmkMode mode = hsmService.getLmkMode();
            log.info("API: Generate key pair, {} bits, LMK mode: {}", modulusBits, mode);

            KeyGenerationResult result = hsmService.generateKeyPair(modulusBits);
            this.lastKeyPair = result;

            response.put("success", true);
            response.put("timestamp", Instant.now().toString());
            response.put("lmkMode", mode.getValue());
            response.put("lmkScheme", result.getLmkScheme());
            response.put("isKeyBlock", result.isKeyBlock());
            response.put("modulusBits", modulusBits);
            response.put("publicKeyHex", result.getPublicKeyHex());
            response.put("publicKeyLength", result.getPublicKeyDer().length);
            response.put("privateKeyLength", result.getPrivateKeyLength());
            response.put("privateKeyHex", result.getPrivateKeyHex());
            response.put("durationMs", System.currentTimeMillis() - start);
            response.put("poolStats", hsmService.getPoolStats());

            // HSM flow explanation
            List<String> flow = new ArrayList<>();
            flow.add("1. EI command → HSM generated RSA-" + modulusBits + " key pair internally");
            if (result.isKeyBlock()) {
                flow.add("2. EI sent with '#' delimiter + Key Block attributes (Mode=" +
                        "S, Version=00, Export=N)");
                flow.add("3. HSM returned: Public key (DER, " + result.getPublicKeyDer().length +
                        " bytes) + Private key (S-prefixed key block, " + result.getPrivateKeyLength() + " bytes)");
                flow.add("4. Private key length field = FFFF (Key Block reserved)");
                flow.add("5. Private key blob starts with 'S' prefix (Key Block scheme)");
            } else {
                flow.add("2. HSM returned: Public key (DER, " + result.getPublicKeyDer().length +
                        " bytes) + Private key (LMK-encrypted, " + result.getPrivateKeyLength() + " bytes)");
                flow.add("3. Application stores key material (public + LMK blob)");
            }
            flow.add("NOTE: Private key never leaves the HSM boundary in cleartext");
            response.put("hsmFlow", flow);

        } catch (PayShieldException e) {
            log.error("HSM error during key generation", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("errorCode", e.getErrorCode());
            response.put("lmkMode", hsmService.getLmkMode().getValue());
            response.put("durationMs", System.currentTimeMillis() - start);
            return ResponseEntity.status(500).body(response);
        } catch (Exception e) {
            log.error("Unexpected error during key generation", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("durationMs", System.currentTimeMillis() - start);
            return ResponseEntity.status(500).body(response);
        }

        return ResponseEntity.ok(response);
    }

    /**
     * Sign a message via HSM.
     * POST /api/sign
     * Body: { "messageHex": "48656C6C6F", "hashId": "06", "padMode": "01" }
     *   or: { "message": "Hello World", "hashId": "06", "padMode": "01" }
     *
     * Prefer 'messageHex' for byte-exact signing; 'message' is UTF-8 encoded as a
     * convenience fallback.
     */
    @PostMapping("/api/sign")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> signMessage(@RequestBody Map<String, Object> request) {
        Map<String, Object> response = new LinkedHashMap<>();
        long start = System.currentTimeMillis();

        try {
            String message = (String) request.get("message");
            String hashId = (String) request.getOrDefault("hashId", "06");
            String padMode = (String) request.getOrDefault("padMode", "01");

            byte[] messageBytes = resolveMessageBytes(request);
            if (messageBytes == null) {
                response.put("success", false);
                response.put("error", "Either 'messageHex' (byte-exact) or 'message' (UTF-8 text) is required");
                return ResponseEntity.badRequest().body(response);
            }

            // Accept an explicit LMK-encrypted private key blob from the UI (multi-slot support).
            // When present it takes priority over lastKeyPair so each of the 3 UI key pair slots
            // can sign independently without overwriting each other in server memory.
            String privateKeyHexOverride = (String) request.get("privateKeyHex");
            byte[] privateKeyBlob;
            boolean isKeyBlock;
            if (privateKeyHexOverride != null && !privateKeyHexOverride.isEmpty()) {
                privateKeyBlob = decodeHexField(privateKeyHexOverride, "privateKeyHex");
                // Key Block blobs start with 'S' (0x53); derive the flag from the blob itself
                isKeyBlock = privateKeyBlob.length > 0 && privateKeyBlob[0] == 'S';
            } else if (lastKeyPair == null) {
                response.put("success", false);
                response.put("error", "No key pair generated yet. Please generate a key pair first.");
                return ResponseEntity.badRequest().body(response);
            } else {
                privateKeyBlob = lastKeyPair.getPrivateKeyLmkEncrypted();
                isKeyBlock = lastKeyPair.isKeyBlock();
            }

            LmkMode mode = hsmService.getLmkMode();
            log.info("API: Sign message ({} bytes), hash={}, pad={}, LMK mode: {}",
                    messageBytes.length, hashId, padMode, mode);

            SigningResult result = hsmService.signMessage(
                    messageBytes,
                    privateKeyBlob,
                    hashId, padMode);
            this.lastSignature = result;
            this.lastSignedMessage = (message != null ? message : "(binary — messageHex)");

            response.put("success", true);
            response.put("timestamp", Instant.now().toString());
            response.put("lmkMode", mode.getValue());
            response.put("isKeyBlock", isKeyBlock);
            response.put("message", message);
            response.put("messageHex", CommandUtils.bytesToHex(messageBytes));
            response.put("messageLength", messageBytes.length);
            response.put("signatureHex", result.getSignatureHex());
            response.put("signatureLength", result.getSignatureLength());
            response.put("hashAlgorithm", result.getHashAlgorithm());
            response.put("padMode", result.getPadMode());
            response.put("durationMs", System.currentTimeMillis() - start);

            List<String> flow = new ArrayList<>();
            flow.add("1. EW command sent to HSM with:");
            flow.add("   - Hash Algorithm: " + result.getHashAlgorithm() + " (ID: " + hashId + ")");
            flow.add("   - Signature Algorithm: RSA (ID: 01)");
            flow.add("   - Pad Mode: " + result.getPadMode() + " (ID: " + padMode + ")");
            flow.add("   - Message: " + messageBytes.length + " bytes");
            if (isKeyBlock) {
                flow.add("   - Private Key: S-prefixed key block blob (flag=99, len=FFFF)");
            } else {
                flow.add("   - Private Key: LMK-encrypted key blob (flag=99)");
            }
            flow.add("2. HSM internally: decrypted key blob under LMK → computed hash → signed");
            flow.add("3. HSM returned: Digital signature (" + result.getSignatureLength() + " bytes)");
            flow.add("NOTE: Private key was decrypted ONLY inside HSM tamper-resistant boundary");
            response.put("hsmFlow", flow);

        } catch (IllegalArgumentException e) {
            log.warn("Invalid input during signing: {}", e.getMessage());
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("durationMs", System.currentTimeMillis() - start);
            return ResponseEntity.badRequest().body(response);
        } catch (PayShieldException e) {
            log.error("HSM error during signing", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("errorCode", e.getErrorCode());
            response.put("durationMs", System.currentTimeMillis() - start);
            return ResponseEntity.status(500).body(response);
        } catch (Exception e) {
            log.error("Unexpected error during signing", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("durationMs", System.currentTimeMillis() - start);
            return ResponseEntity.status(500).body(response);
        }

        return ResponseEntity.ok(response);
    }

    /**
     * Verify a signature via HSM.
     * POST /api/verify
     *
     * Two modes:
     *
     * Mode A — Full EO + EY (supply raw DER public key):
     *   Body: { "message": "...", "signatureHex": "...", "publicKeyHex": "<DER hex>",
     *           "hashId": "06", "padMode": "01" }
     *   Response includes "eoPublicKeyHex" (Key Block) or "eoMacHex"+"eoPublicKeyDerHex"
     *   (Variant) so the caller can save the EO-formatted key for future EY-only calls.
     *
     * Mode B — EY only (supply pre-formatted EO key, skips EO round-trip):
     *   Key Block LMK: { ..., "eoPublicKeyHex": "<S-prefixed blob hex>" }
     *   Variant LMK:   { ..., "eoCombinedHex": "<MAC(8 chars) + DER hex>" }
     *                  or separately: { ..., "eoMacHex": "...", "eoPublicKeyDerHex": "..." }
     *   The combined format is preferred: first 8 hex chars = 4-byte MAC, rest = DER.
     */
    @PostMapping("/api/verify")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> verifySignature(@RequestBody Map<String, Object> request) {
        Map<String, Object> response = new LinkedHashMap<>();
        long start = System.currentTimeMillis();

        try {
            String signatureHex   = (String) request.get("signatureHex");
            String publicKeyHex   = (String) request.get("publicKeyHex");
            String hashId  = (String) request.getOrDefault("hashId",  "06");
            String padMode = (String) request.getOrDefault("padMode", "01");

            // Pre-formatted EO key fields (Mode B)
            String eoPublicKeyHex    = (String) request.get("eoPublicKeyHex");    // Key Block blob
            String eoCombinedHex     = (String) request.get("eoCombinedHex");     // Variant: MAC(8)+DER
            String eoMacHex          = (String) request.get("eoMacHex");           // Variant MAC (legacy separate)
            String eoPublicKeyDerHex = (String) request.get("eoPublicKeyDerHex"); // Variant DER (legacy separate)

            // Expand eoCombinedHex into MAC + DER if provided (first 8 hex chars = 4-byte MAC)
            if (eoCombinedHex != null && !eoCombinedHex.isEmpty() && eoCombinedHex.length() > 8) {
                eoMacHex          = eoCombinedHex.substring(0, 8);
                eoPublicKeyDerHex = eoCombinedHex.substring(8);
            }

            boolean hasEoKey = (eoPublicKeyHex != null && !eoPublicKeyHex.isEmpty())
                    || (eoMacHex != null && !eoMacHex.isEmpty()
                        && eoPublicKeyDerHex != null && !eoPublicKeyDerHex.isEmpty());

            byte[] messageBytes = resolveMessageBytes(request);
            if (messageBytes == null || signatureHex == null
                    || (!hasEoKey && publicKeyHex == null)) {
                response.put("success", false);
                response.put("error",
                        "message (or messageHex) and signatureHex are always required. " +
                        "Also supply either 'publicKeyHex' (raw DER, runs EO+EY) " +
                        "or 'eoPublicKeyHex'/'eoMacHex'+'eoPublicKeyDerHex' (pre-formatted, EY only).");
                return ResponseEntity.badRequest().body(response);
            }

            LmkMode mode = hsmService.getLmkMode();
            byte[] signature = decodeHexField(signatureHex, "signatureHex");

            PublicKeyImportResult importResult;
            boolean skippedEo;

            if (hasEoKey) {
                // ── Mode B: EY only, reconstruct PublicKeyImportResult from saved EO data ──
                if (eoPublicKeyHex != null && !eoPublicKeyHex.isEmpty()) {
                    // Key Block path
                    byte[] keyBlock = decodeHexField(eoPublicKeyHex, "eoPublicKeyHex");
                    importResult = PublicKeyImportResult.keyBlockResult(keyBlock);
                    log.info("API: Verify (EY only / Key Block), msg={} bytes, LMK mode: {}",
                            messageBytes.length, mode);
                } else {
                    // Variant path
                    byte[] mac = decodeHexField(eoMacHex, "eoMacHex");
                    byte[] der = decodeHexField(eoPublicKeyDerHex, "eoPublicKeyDerHex");
                    importResult = new PublicKeyImportResult(mac, der);
                    log.info("API: Verify (EY only / Variant), msg={} bytes, LMK mode: {}",
                            messageBytes.length, mode);
                }
                skippedEo = true;
            } else {
                // ── Mode A: Full EO + EY, import raw DER public key ──
                byte[] publicKeyDer = decodeHexField(publicKeyHex, "publicKeyHex");
                log.info("API: Verify (EO+EY), msg={} bytes, pubKey={} hex chars, LMK mode: {}",
                        messageBytes.length, publicKeyHex.length(), mode);
                importResult = hsmService.importPublicKeyForVerification(publicKeyDer);
                skippedEo = false;
            }

            VerificationResult result = hsmService.verifySignature(
                    signature, messageBytes, importResult, hashId, padMode);

            response.put("success", true);
            response.put("timestamp", Instant.now().toString());
            response.put("lmkMode", mode.getValue());
            response.put("skippedEo", skippedEo);
            response.put("valid", result.isValid());
            response.put("errorCode", result.getErrorCode());
            response.put("errorDescription", result.getErrorDescription());
            response.put("rawResponseHex", result.getRawResponseHex());
            response.put("durationMs", System.currentTimeMillis() - start);

            // ── Expose EO-formatted key so the caller can save it for future EY-only calls ──
            if (!skippedEo) {
                if (mode == LmkMode.KEYBLOCK) {
                    response.put("eoPublicKeyHex", importResult.getPublicKeyBlockHex());
                } else {
                    // Variant: expose as one combined string (MAC 8 hex chars + DER hex)
                    // so the caller has a single value to copy/save, matching Key Block UX.
                    String macHex = importResult.getMacHex();
                    String derHex = CommandUtils.bytesToHex(importResult.getPublicKeyDer());
                    response.put("eoCombinedHex",     macHex + derHex);
                    response.put("eoMacHex",           macHex);          // also exposed separately
                    response.put("eoPublicKeyDerHex",  derHex);           // for reference
                }
            }

            if (result.isValid()) {
                response.put("verdict", "SIGNATURE VALID");
                response.put("explanation", "The HSM confirmed that the signature matches the message " +
                        "when verified with the provided public key. Error code 00 = No error.");
            } else if ("02".equals(result.getErrorCode())) {
                response.put("verdict", "SIGNATURE INVALID");
                response.put("explanation", "The HSM detected a signature mismatch. Error code 02 = " +
                        "Signature verification failure.");
            } else if ("01".equals(result.getErrorCode())) {
                response.put("verdict", "MAC VERIFICATION FAILED");
                response.put("explanation", mode == LmkMode.KEYBLOCK
                        ? "The HSM could not verify the key block MAC. Error code 01. " +
                          "The public key block may be corrupted or from a different LMK."
                        : "The HSM could not verify the MAC on the public key. Error code 01 = " +
                          "MAC verification failure.");
            } else {
                response.put("verdict", "HSM ERROR");
                response.put("explanation", "The HSM returned error code " + result.getErrorCode() +
                        ": " + result.getErrorDescription());
            }

            List<String> flow = new ArrayList<>();
            if (skippedEo) {
                flow.add("EO step SKIPPED — using pre-formatted public key from saved EO result");
                flow.add("1. EY command sent directly with " +
                        (mode == LmkMode.KEYBLOCK ? "S-prefixed key block" : "MAC + DER"));
            } else if (mode == LmkMode.KEYBLOCK) {
                flow.add("1. EO command → public key imported with '#' + Key Block attributes");
                flow.add("   HSM returned: S-prefixed public key block (MAC embedded in key block)");
                flow.add("   → Save 'eoPublicKeyHex' from this response to reuse EY-only next time");
                flow.add("2. EY command sent with S-prefixed public key block");
            } else {
                flow.add("1. EO command → public key imported, HSM computed MAC under LMK pair 36-37");
                flow.add("   → Save 'eoCombinedHex' (MAC 8 chars + DER) to reuse EY-only next time");
                flow.add("2. EY command sent with MAC + DER public key");
            }
            flow.add("3. HSM internally: verified key integrity → computed hash → RSA verification");
            flow.add("4. HSM returned: EZ response, error code = " + result.getErrorCode() +
                    " (" + result.getErrorDescription() + ")");
            response.put("hsmFlow", flow);

        } catch (IllegalArgumentException e) {
            log.warn("Invalid input during verification: {}", e.getMessage());
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("durationMs", System.currentTimeMillis() - start);
            return ResponseEntity.badRequest().body(response);
        } catch (PayShieldException e) {
            log.error("HSM error during verification", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("errorCode", e.getErrorCode());
            response.put("durationMs", System.currentTimeMillis() - start);
            return ResponseEntity.status(500).body(response);
        } catch (Exception e) {
            log.error("Unexpected error during verification", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("durationMs", System.currentTimeMillis() - start);
            return ResponseEntity.status(500).body(response);
        }

        return ResponseEntity.ok(response);
    }

    /**
     * Import a public key via EO command (one-time operation).
     *
     * Run this ONCE for a given public key and save the returned EO-formatted key
     * to your local DB / text file. Then use that saved key in /api/verify with
     * 'eoPublicKeyHex' (Key Block) or 'eoMacHex'+'eoPublicKeyDerHex' (Variant)
     * to skip the EO round-trip on every subsequent verification.
     *
     * POST /api/import-pubkey
     * Body: { "publicKeyHex": "<DER hex>" }
     */
    @PostMapping("/api/import-pubkey")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> importPublicKey(@RequestBody Map<String, Object> request) {
        Map<String, Object> response = new LinkedHashMap<>();
        long start = System.currentTimeMillis();

        try {
            String publicKeyHex = (String) request.get("publicKeyHex");
            if (publicKeyHex == null || publicKeyHex.isEmpty()) {
                response.put("success", false);
                response.put("error", "publicKeyHex (raw DER hex) is required");
                return ResponseEntity.badRequest().body(response);
            }

            LmkMode mode = hsmService.getLmkMode();
            log.info("API: Import public key via EO, pubKey={} hex chars, LMK mode: {}",
                    publicKeyHex.length(), mode);

            byte[] publicKeyDer = decodeHexField(publicKeyHex, "publicKeyHex");
            PublicKeyImportResult result = hsmService.importPublicKeyForVerification(publicKeyDer);

            response.put("success", true);
            response.put("timestamp", Instant.now().toString());
            response.put("lmkMode", mode.getValue());
            response.put("isKeyBlock", result.isKeyBlock());
            response.put("durationMs", System.currentTimeMillis() - start);

            if (mode == LmkMode.KEYBLOCK) {
                response.put("eoPublicKeyHex", result.getPublicKeyBlockHex());
                response.put("note",
                        "Save 'eoPublicKeyHex'. Use it in /api/verify with field 'eoPublicKeyHex' " +
                        "to skip EO and go straight to EY on every subsequent verification.");
            } else {
                String macHex = result.getMacHex();
                String derHex = CommandUtils.bytesToHex(result.getPublicKeyDer());
                response.put("eoCombinedHex",    macHex + derHex);   // single value to save
                response.put("eoMacHex",          macHex);            // also separately for reference
                response.put("eoPublicKeyDerHex", derHex);
                response.put("note",
                        "Save 'eoCombinedHex' (first 8 chars = MAC, rest = DER public key). " +
                        "Use it in /api/verify with field 'eoCombinedHex' to skip EO.");
            }

            response.put("hsmFlow", List.of(
                    "1. EO command sent to HSM with DER public key (" + publicKeyDer.length + " bytes)",
                    mode == LmkMode.KEYBLOCK
                            ? "2. HSM returned: S-prefixed key block (" + result.getPublicKeyBlock().length + " bytes) — MAC embedded"
                            : "2. HSM returned: MAC (4 bytes, LMK pair 36-37) + DER public key (" + result.getPublicKeyDer().length + " bytes)",
                    "3. Save the EO result — it stays valid as long as the HSM LMK is unchanged",
                    "4. Use the saved EO key in /api/verify to call EY only (no EO round-trip)"
            ));

        } catch (IllegalArgumentException e) {
            log.warn("Invalid input during public key import: {}", e.getMessage());
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("durationMs", System.currentTimeMillis() - start);
            return ResponseEntity.badRequest().body(response);
        } catch (PayShieldException e) {
            log.error("HSM error during public key import", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("errorCode", e.getErrorCode());
            response.put("durationMs", System.currentTimeMillis() - start);
            return ResponseEntity.status(500).body(response);
        } catch (Exception e) {
            log.error("Unexpected error during public key import", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("durationMs", System.currentTimeMillis() - start);
            return ResponseEntity.status(500).body(response);
        }

        return ResponseEntity.ok(response);
    }

    /**
     * Verify a signature in software (no HSM call).
     *
     * Verification only needs the signer's public key — public material — so this runs
     * entirely on the JVM. No HSM connection, no LMK, immune to LMK-mismatch errors.
     * Ideal for high-volume inbound checks (e.g. PayNet-signed messages).
     *
     * POST /api/verify-software
     * Body: { "message": "...", "signatureHex": "...", "publicKeyHex": "...",
     *         "hashId": "06", "padMode": "01" }
     */
    @PostMapping("/api/verify-software")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> verifySignatureOffHsm(@RequestBody Map<String, Object> request) {
        Map<String, Object> response = new LinkedHashMap<>();
        long start = System.currentTimeMillis();

        try {
            String signatureHex = (String) request.get("signatureHex");
            String publicKeyHex = (String) request.get("publicKeyHex");
            String hashId = (String) request.getOrDefault("hashId", "06");
            String padMode = (String) request.getOrDefault("padMode", "01");

            byte[] messageBytes = resolveMessageBytes(request);
            if (messageBytes == null || signatureHex == null || publicKeyHex == null) {
                response.put("success", false);
                response.put("error", "message (or messageHex), signatureHex, and publicKeyHex are all required");
                return ResponseEntity.badRequest().body(response);
            }

            log.info("API: Verify signature in SOFTWARE (no HSM), message={} bytes, pubKey={} hex chars",
                    messageBytes.length, publicKeyHex.length());

            byte[] signature = decodeHexField(signatureHex, "signatureHex");
            byte[] publicKeyDer = decodeHexField(publicKeyHex, "publicKeyHex");

            VerificationResult result = hsmService.verifySignatureOffHsm(
                    signature, messageBytes, publicKeyDer, hashId, padMode);

            response.put("success", true);
            response.put("timestamp", Instant.now().toString());
            response.put("verificationMode", "software");
            response.put("valid", result.isValid());
            response.put("errorCode", result.getErrorCode());
            response.put("errorDescription", result.getErrorDescription());
            response.put("hashAlgorithm", CommandUtils.decodeHashAlgorithm(hashId));
            response.put("padMode", CommandUtils.decodePadMode(padMode));
            response.put("durationMs", System.currentTimeMillis() - start);

            if (result.isValid()) {
                response.put("verdict", "SIGNATURE VALID");
                response.put("explanation", "The JVM confirmed the signature matches the message " +
                        "using the provided public key. No HSM was involved.");
            } else {
                response.put("verdict", "SIGNATURE INVALID");
                response.put("explanation", "The signature does not match the message under the " +
                        "provided public key (error code 02 = signature mismatch).");
            }

            response.put("flow", List.of(
                    "1. Parsed public key DER (X.509 SubjectPublicKeyInfo) via JDK KeyFactory",
                    "2. Selected algorithm: " + CommandUtils.decodeHashAlgorithm(hashId) +
                            " + " + CommandUtils.decodePadMode(padMode),
                    "3. Recomputed hash over the message and ran RSA verification on the JVM",
                    "4. Result: " + (result.isValid() ? "VALID" : "INVALID") +
                            " (error code " + result.getErrorCode() + ")",
                    "NOTE: No HSM connection, no LMK, no private key — public key only"
            ));

        } catch (IllegalArgumentException e) {
            log.warn("Invalid input during software verification: {}", e.getMessage());
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("durationMs", System.currentTimeMillis() - start);
            return ResponseEntity.badRequest().body(response);
        } catch (PayShieldException e) {
            log.error("Error during software verification", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("errorCode", e.getErrorCode());
            response.put("durationMs", System.currentTimeMillis() - start);
            return ResponseEntity.status(500).body(response);
        } catch (Exception e) {
            log.error("Unexpected error during software verification", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("durationMs", System.currentTimeMillis() - start);
            return ResponseEntity.status(500).body(response);
        }

        return ResponseEntity.ok(response);
    }

    /**
     * Get current state.
     */
    @GetMapping("/api/state")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getState() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("lmkMode", hsmService.getLmkMode().getValue());
        response.put("hasKeyPair", lastKeyPair != null);
        response.put("hasSignature", lastSignature != null);

        if (lastKeyPair != null) {
            response.put("publicKeyHex", lastKeyPair.getPublicKeyHex());
            response.put("modulusBits", lastKeyPair.getModulusLengthBits());
            response.put("isKeyBlock", lastKeyPair.isKeyBlock());
            response.put("lmkScheme", lastKeyPair.getLmkScheme());
        }
        if (lastSignature != null) {
            response.put("signatureHex", lastSignature.getSignatureHex());
            response.put("signedMessage", lastSignedMessage);
        }

        response.put("poolStats", hsmService.getPoolStats());
        return ResponseEntity.ok(response);
    }

    // ===== CSR GENERATION =====

    /**
     * Generate a Certificate Signing Request (CSR) via HSM QE command.
     * Requires Key Block LMK mode and an existing key pair.
     *
     * POST /api/generate-csr
     * Body: {
     *   "commonName": "BKRM-RPP-SIGNING",
     *   "organization": "Bank Kerjasama Rakyat Malaysia Berhad",
     *   "orgUnit": "IT",
     *   "locality": "Kuala Lumpur",
     *   "state": "Wilayah Persekutuan",
     *   "country": "MY",
     *   "pemOutput": true
     * }
     */
    @PostMapping("/api/generate-csr")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> generateCsr(@RequestBody Map<String, Object> request) {
        Map<String, Object> response = new LinkedHashMap<>();
        long start = System.currentTimeMillis();

        try {
            String commonName = (String) request.getOrDefault("commonName", "BKRM-RPP-SIGNING");
            String organization = (String) request.getOrDefault("organization", "Bank Kerjasama Rakyat Malaysia Berhad");
            String orgUnit = (String) request.getOrDefault("orgUnit", "IT");
            String locality = (String) request.getOrDefault("locality", "Kuala Lumpur");
            String state = (String) request.getOrDefault("state", "Wilayah Persekutuan");
            String country = (String) request.getOrDefault("country", "MY");
            String outputFormatStr = (String) request.getOrDefault("outputFormat", "0");
            boolean pemOutput = "0".equals(outputFormatStr);

            LmkMode mode = hsmService.getLmkMode();
            log.info("API: Generate CSR, CN={}, LMK mode: {}", commonName, mode);

            if (lastKeyPair == null) {
                response.put("success", false);
                response.put("error", "No key pair generated yet. Please generate a key pair first.");
                return ResponseEntity.badRequest().body(response);
            }

            CsrGenerationResult result = hsmService.generateCsr(
                    lastKeyPair.getPublicKeyDer(),
                    lastKeyPair.getPrivateKeyLmkEncrypted(),
                    commonName, organization, orgUnit, locality, state, country, pemOutput);

            response.put("success", true);
            response.put("timestamp", Instant.now().toString());
            response.put("lmkMode", mode.getValue());
            response.put("csrLength", result.getCsrLength());
            response.put("csrFormat", pemOutput ? "PEM" : "HexDER");
            response.put("csrData", result.isPem() ? result.getFormattedPem() : result.getCsrData());
            response.put("durationMs", System.currentTimeMillis() - start);

            // Subject DN
            Map<String, String> subject = new LinkedHashMap<>();
            subject.put("CN", commonName);
            subject.put("O", organization);
            subject.put("OU", orgUnit);
            subject.put("L", locality);
            subject.put("ST", state);
            subject.put("C", country);
            response.put("subjectDN", subject);

            response.put("hsmFlow", List.of(
                    "1. QE command sent to HSM with:",
                    "   - CSR Type: PKCS#10",
                    "   - Public Key: " + lastKeyPair.getPublicKeyDer().length + " bytes (DER)",
                    "   - Private Key: " + lastKeyPair.getPrivateKeyLmkEncrypted().length + " bytes (S-prefixed Key Block)",
                    "   - Hash: SHA-256, Pad: PKCS#1 v1.5",
                    "   - Subject: CN=" + commonName + ", O=" + organization + ", C=" + country,
                    "2. HSM internally: built PKCS#10 TBS structure → signed with private key",
                    "3. HSM returned: Complete CSR (" + result.getCsrLength() + " chars, " + (pemOutput ? "PEM" : "HexDER") + ")",
                    "NOTE: Private key NEVER left the HSM — CSR was fully assembled inside HSM"
            ));

        } catch (PayShieldException e) {
            log.error("HSM error during CSR generation", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("errorCode", e.getErrorCode());
            response.put("durationMs", System.currentTimeMillis() - start);
            return ResponseEntity.status(500).body(response);
        } catch (Exception e) {
            log.error("Unexpected error during CSR generation", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("durationMs", System.currentTimeMillis() - start);
            return ResponseEntity.status(500).body(response);
        }

        return ResponseEntity.ok(response);
    }

    // ===== DIAGNOSTIC ENDPOINTS =====

    @GetMapping("/api/diagnostics")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> performDiagnostics() {
        Map<String, Object> response = new LinkedHashMap<>();
        long start = System.currentTimeMillis();

        try {
            log.info("API: Perform Diagnostics (NC command)");
            String header = "0000";

            byte[] ncCmd = DiagnosticCommands.buildNC(header);
            log.debug("NC command hex: {}", CommandUtils.bytesToHex(ncCmd));

            byte[] ncResp = hsmService.executeRaw(ncCmd);
            Map<String, String> result = DiagnosticCommands.parseNCResponse(ncResp, 4);

            response.put("success", "OK".equals(result.get("status")));
            response.putAll(result);
            response.put("lmkMode", hsmService.getLmkMode().getValue());
            response.put("durationMs", System.currentTimeMillis() - start);

        } catch (Exception e) {
            log.error("Diagnostics failed", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("durationMs", System.currentTimeMillis() - start);
            return ResponseEntity.status(500).body(response);
        }

        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/hsm-status")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getHsmStatus() {
        Map<String, Object> response = new LinkedHashMap<>();
        long start = System.currentTimeMillis();

        try {
            log.info("API: HSM Status (NO command)");
            String header = "0000";

            byte[] noCmd = DiagnosticCommands.buildNO(header, "00");
            log.debug("NO command hex: {}", CommandUtils.bytesToHex(noCmd));

            byte[] noResp = hsmService.executeRaw(noCmd);
            Map<String, String> result = DiagnosticCommands.parseNOResponse(noResp, 4);

            response.put("success", "OK".equals(result.get("status")));
            response.putAll(result);
            response.put("lmkMode", hsmService.getLmkMode().getValue());
            response.put("durationMs", System.currentTimeMillis() - start);

        } catch (Exception e) {
            log.error("HSM Status failed", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("durationMs", System.currentTimeMillis() - start);
            return ResponseEntity.status(500).body(response);
        }

        return ResponseEntity.ok(response);
    }

    // ===== Helpers =====

    private String truncateHex(String hex, int maxChars) {
        if (hex.length() <= maxChars) return hex;
        return hex.substring(0, maxChars) + "... (" + hex.length() + " total chars)";
    }

    /**
     * Resolve the canonical message bytes to sign or verify.
     *
     * Prefers byte-exact {@code messageHex} so that verification runs over the exact
     * bytes that were signed (no JSON/Unicode re-encoding drift). Falls back to UTF-8
     * encoding of the plain {@code message} string for convenience / the demo UI.
     *
     * @return the message bytes, or {@code null} if neither field was supplied
     * @throws IllegalArgumentException if {@code messageHex} is present but malformed
     */
    private static byte[] resolveMessageBytes(Map<String, Object> request) {
        String messageHex = (String) request.get("messageHex");
        if (messageHex != null && !messageHex.isEmpty()) {
            return decodeHexField(messageHex, "messageHex");
        }
        String message = (String) request.get("message");
        if (message != null && !message.isEmpty()) {
            return message.getBytes(StandardCharsets.UTF_8);
        }
        return null;
    }

    /**
     * Decode a required hex field, re-tagging any validation error with the field name
     * so the caller gets a clear 400 (e.g. "signatureHex: hex input must have an even
     * number of digits").
     */
    private static byte[] decodeHexField(String value, String fieldName) {
        try {
            return CommandUtils.hexToBytes(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(fieldName + ": " + e.getMessage());
        }
    }
}