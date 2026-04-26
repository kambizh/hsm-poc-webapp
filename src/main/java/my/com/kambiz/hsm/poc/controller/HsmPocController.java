package my.com.kambiz.hsm.poc.controller;

import my.com.kambiz.hsm.command.CommandUtils;
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
            log.info("API: Generate key pair, {} bits", modulusBits);
            log.info("modulusBits value from UI: {}", modulusBits);

            KeyGenerationResult result = hsmService.generateKeyPair(modulusBits);
            this.lastKeyPair = result;

            response.put("success", true);
            response.put("timestamp", Instant.now().toString());
            response.put("modulusBits", modulusBits);
            response.put("publicKeyHex", result.getPublicKeyHex());
            response.put("publicKeyLength", result.getPublicKeyDer().length);
            response.put("privateKeyLength", result.getPrivateKeyLength());
            response.put("privateKeyHex", truncateHex(result.getPrivateKeyHex(), 64));
            response.put("durationMs", System.currentTimeMillis() - start);
            response.put("poolStats", hsmService.getPoolStats());

            // HSM flow explanation
            response.put("hsmFlow", List.of(
                    "1. EI command → HSM generated RSA-" + modulusBits + " key pair internally",
                    "2. HSM returned: Public key (DER-encoded, " + result.getPublicKeyDer().length + " bytes) + Private key (LMK-encrypted, " + result.getPrivateKeyLength() + " bytes)",
                    "3. LA command → LMK-encrypted private key stored in HSM user storage at index K000",
                    "4. EO command → Public key imported, MAC generated for future verification",
                    "NOTE: Private key NEVER leaves the HSM in cleartext - only LMK-encrypted form is handled"
            ));

        } catch (PayShieldException e) {
            log.error("HSM error during key generation", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            response.put("errorCode", e.getErrorCode());
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
     * Body: { "message": "Hello World", "hashId": "05", "padMode": "01" }
     */
    @PostMapping("/api/sign")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> signMessage(@RequestBody Map<String, Object> request) {
        Map<String, Object> response = new LinkedHashMap<>();
        long start = System.currentTimeMillis();

        try {
            String message = (String) request.get("message");
            String hashId = (String) request.getOrDefault("hashId", "05");
            String padMode = (String) request.getOrDefault("padMode", "01");

            if (message == null || message.isEmpty()) {
                response.put("success", false);
                response.put("error", "Message is required");
                return ResponseEntity.badRequest().body(response);
            }

            if (lastKeyPair == null) {
                response.put("success", false);
                response.put("error", "No key pair generated yet. Please generate a key pair first.");
                return ResponseEntity.badRequest().body(response);
            }

            log.info("API: Sign message ({} bytes), hash={}, pad={}", message.length(), hashId, padMode);

            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
            SigningResult result = hsmService.signMessage(messageBytes, hashId, padMode);
            this.lastSignature = result;
            this.lastSignedMessage = message;

            response.put("success", true);
            response.put("timestamp", Instant.now().toString());
            response.put("message", message);
            response.put("messageHex", CommandUtils.bytesToHex(messageBytes));
            response.put("messageLength", messageBytes.length);
            response.put("signatureHex", result.getSignatureHex());
            response.put("signatureLength", result.getSignatureLength());
            response.put("hashAlgorithm", result.getHashAlgorithm());
            response.put("padMode", result.getPadMode());
            response.put("durationMs", System.currentTimeMillis() - start);

            response.put("hsmFlow", List.of(
                    "1. EW command sent to HSM with:",
                    "   - Hash Algorithm: " + result.getHashAlgorithm() + " (ID: " + hashId + ")",
                    "   - Signature Algorithm: RSA (ID: 01)",
                    "   - Pad Mode: " + result.getPadMode() + " (ID: " + padMode + ")",
                    "   - Message: " + messageBytes.length + " bytes",
                    "   - Private Key: referenced by K000 in HSM user storage (flag=91)",
                    "2. HSM internally: retrieved LMK-encrypted key from K000 → decrypted under LMK → computed hash → signed",
                    "3. HSM returned: Digital signature (" + result.getSignatureLength() + " bytes)",
                    "NOTE: Private key was decrypted ONLY inside HSM tamper-resistant boundary"
            ));

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
     * Body: {
     *   "message": "Hello World",
     *   "signatureHex": "ABCD...",
     *   "publicKeyHex": "3082...",
     *   "hashId": "05",
     *   "padMode": "01"
     * }
     */
    @PostMapping("/api/verify")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> verifySignature(@RequestBody Map<String, Object> request) {
        Map<String, Object> response = new LinkedHashMap<>();
        long start = System.currentTimeMillis();

        try {
            String message = (String) request.get("message");
            String signatureHex = (String) request.get("signatureHex");
            String publicKeyHex = (String) request.get("publicKeyHex");
            String hashId = (String) request.getOrDefault("hashId", "05");
            String padMode = (String) request.getOrDefault("padMode", "01");

            if (message == null || signatureHex == null || publicKeyHex == null) {
                response.put("success", false);
                response.put("error", "message, signatureHex, and publicKeyHex are all required");
                return ResponseEntity.badRequest().body(response);
            }

            log.info("API: Verify signature, message={} bytes, pubKey={} hex chars",
                    message.length(), publicKeyHex.length());

            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] signature = CommandUtils.hexToBytes(signatureHex);
            byte[] publicKeyDer = CommandUtils.hexToBytes(publicKeyHex);

            VerificationResult result = hsmService.verifySignature(
                    signature, messageBytes, publicKeyDer, hashId, padMode);

            response.put("success", true);
            response.put("timestamp", Instant.now().toString());
            response.put("valid", result.isValid());
            response.put("errorCode", result.getErrorCode());
            response.put("errorDescription", result.getErrorDescription());
            response.put("rawResponseHex", result.getRawResponseHex());
            response.put("durationMs", System.currentTimeMillis() - start);

            // Explanation of the result
            if (result.isValid()) {
                response.put("verdict", "SIGNATURE VALID");
                response.put("explanation", "The HSM confirmed that the signature matches the message " +
                        "when verified with the provided public key. Error code 00 = No error.");
            } else if ("02".equals(result.getErrorCode())) {
                response.put("verdict", "SIGNATURE INVALID");
                response.put("explanation", "The HSM detected a signature mismatch. Error code 02 = " +
                        "Signature verification failure. This means either: (a) the message was tampered with, " +
                        "(b) the signature was tampered with, or (c) the wrong public key was used " +
                        "(it does not correspond to the private key that created the signature).");
            } else if ("01".equals(result.getErrorCode())) {
                response.put("verdict", "MAC VERIFICATION FAILED");
                response.put("explanation", "The HSM could not verify the MAC on the public key. Error code 01 = " +
                        "MAC verification failure. This means the public key DER data is corrupted or was " +
                        "not properly imported via EO command. The EO MAC (computed with LMK 36-37) " +
                        "does not match the public key provided in the EY command.");
            } else {
                response.put("verdict", "HSM ERROR");
                response.put("explanation", "The HSM returned error code " + result.getErrorCode() +
                        ": " + result.getErrorDescription() + ". This is an operational error, not a " +
                        "signature mismatch.");
            }

            response.put("hsmFlow", List.of(
                    "1. EO command → public key imported, HSM generated MAC using LMK pair 36-37",
                    "2. EY command sent to HSM with:",
                    "   - Signature: " + signature.length + " bytes",
                    "   - Message: " + messageBytes.length + " bytes",
                    "   - Public Key: " + publicKeyDer.length + " bytes (DER)",
                    "   - MAC: from EO (protects public key integrity)",
                    "3. HSM internally: verified MAC on public key → computed hash of message → " +
                            "performed RSA verification using public key",
                    "4. HSM returned: EZ response, error code = " + result.getErrorCode() +
                            " (" + result.getErrorDescription() + ")"
            ));

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
     * Get current state (last generated key pair, last signature, etc.)
     */
    @GetMapping("/api/state")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getState() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("hasKeyPair", lastKeyPair != null);
        response.put("hasSignature", lastSignature != null);

        if (lastKeyPair != null) {
            response.put("publicKeyHex", lastKeyPair.getPublicKeyHex());
            response.put("modulusBits", lastKeyPair.getModulusLengthBits());
        }
        if (lastSignature != null) {
            response.put("signatureHex", lastSignature.getSignatureHex());
            response.put("signedMessage", lastSignedMessage);
        }

        response.put("poolStats", hsmService.getPoolStats());
        return ResponseEntity.ok(response);
    }

    // ===== DIAGNOSTIC ENDPOINTS =====
    // Add these methods to your HsmPocController class

    /**
     * NC - Perform Diagnostics (no authorization required)
     * Tests processor, software, LMK. Returns LMK check value + firmware.
     * GET /api/diagnostics
     */
    @GetMapping("/api/diagnostics")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> performDiagnostics() {
        Map<String, Object> response = new LinkedHashMap<>();
        long start = System.currentTimeMillis();

        try {
            log.info("API: Perform Diagnostics (NC command)");
            String header = "0000"; // or use properties.getHeaderLength()

            // Build and send NC command
            byte[] ncCmd = DiagnosticCommands.buildNC(header);
            log.debug("NC command hex: {}", CommandUtils.bytesToHex(ncCmd));

            byte[] ncResp = hsmService.executeRaw(ncCmd);
            Map<String, String> result = DiagnosticCommands.parseNCResponse(ncResp, 4);

            response.put("success", "OK".equals(result.get("status")));
            response.putAll(result);
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

    /**
     * NO - HSM Status (no authorization required)
     * Returns HSM status: firmware, buffer size, sockets, ethernet type.
     * GET /api/hsm-status
     */
    @GetMapping("/api/hsm-status")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getHsmStatus() {
        Map<String, Object> response = new LinkedHashMap<>();
        long start = System.currentTimeMillis();

        try {
            log.info("API: HSM Status (NO command)");
            String header = "0000";

            // Build and send NO command with mode 00
            byte[] noCmd = DiagnosticCommands.buildNO(header, "00");
            log.debug("NO command hex: {}", CommandUtils.bytesToHex(noCmd));

            byte[] noResp = hsmService.executeRaw(noCmd);
            Map<String, String> result = DiagnosticCommands.parseNOResponse(noResp, 4);

            response.put("success", "OK".equals(result.get("status")));
            response.putAll(result);
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
}
