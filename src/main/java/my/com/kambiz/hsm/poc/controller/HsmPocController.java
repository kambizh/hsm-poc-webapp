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
            response.put("privateKeyHex", truncateHex(result.getPrivateKeyHex(), 64));
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
     * Body: { "message": "Hello World", "hashId": "06", "padMode": "01" }
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

            LmkMode mode = hsmService.getLmkMode();
            log.info("API: Sign message ({} bytes), hash={}, pad={}, LMK mode: {}",
                    message.length(), hashId, padMode, mode);

            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
            SigningResult result = hsmService.signMessage(messageBytes, hashId, padMode);
            this.lastSignature = result;
            this.lastSignedMessage = message;

            response.put("success", true);
            response.put("timestamp", Instant.now().toString());
            response.put("lmkMode", mode.getValue());
            response.put("isKeyBlock", lastKeyPair.isKeyBlock());
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
            if (lastKeyPair.isKeyBlock()) {
                flow.add("   - Private Key: S-prefixed key block blob (flag=99, len=FFFF)");
            } else {
                flow.add("   - Private Key: LMK-encrypted key blob (flag=99)");
            }
            flow.add("2. HSM internally: decrypted key blob under LMK → computed hash → signed");
            flow.add("3. HSM returned: Digital signature (" + result.getSignatureLength() + " bytes)");
            flow.add("NOTE: Private key was decrypted ONLY inside HSM tamper-resistant boundary");
            response.put("hsmFlow", flow);

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
            String hashId = (String) request.getOrDefault("hashId", "06");
            String padMode = (String) request.getOrDefault("padMode", "01");

            if (message == null || signatureHex == null || publicKeyHex == null) {
                response.put("success", false);
                response.put("error", "message, signatureHex, and publicKeyHex are all required");
                return ResponseEntity.badRequest().body(response);
            }

            LmkMode mode = hsmService.getLmkMode();
            log.info("API: Verify signature, message={} bytes, pubKey={} hex chars, LMK mode: {}",
                    message.length(), publicKeyHex.length(), mode);

            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] signature = CommandUtils.hexToBytes(signatureHex);
            byte[] publicKeyDer = CommandUtils.hexToBytes(publicKeyHex);

            VerificationResult result = hsmService.verifySignature(
                    signature, messageBytes, publicKeyDer, hashId, padMode);

            response.put("success", true);
            response.put("timestamp", Instant.now().toString());
            response.put("lmkMode", mode.getValue());
            response.put("valid", result.isValid());
            response.put("errorCode", result.getErrorCode());
            response.put("errorDescription", result.getErrorDescription());
            response.put("rawResponseHex", result.getRawResponseHex());
            response.put("durationMs", System.currentTimeMillis() - start);

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
            if (mode == LmkMode.KEYBLOCK) {
                flow.add("1. EO command → public key imported with '#' + Key Block attributes");
                flow.add("   HSM returned: S-prefixed public key block (MAC embedded in key block)");
                flow.add("2. EY command sent with S-prefixed public key block (no separate MAC)");
            } else {
                flow.add("1. EO command → public key imported, HSM generated MAC using LMK pair 36-37");
                flow.add("2. EY command sent with MAC + DER public key");
            }
            flow.add("3. HSM internally: verified key integrity → computed hash → RSA verification");
            flow.add("4. HSM returned: EZ response, error code = " + result.getErrorCode() +
                    " (" + result.getErrorDescription() + ")");
            response.put("hsmFlow", flow);

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
            boolean pemOutput = (boolean) request.getOrDefault("pemOutput", true);

            LmkMode mode = hsmService.getLmkMode();
            log.info("API: Generate CSR, CN={}, LMK mode: {}", commonName, mode);

            if (lastKeyPair == null) {
                response.put("success", false);
                response.put("error", "No key pair generated yet. Please generate a key pair first.");
                return ResponseEntity.badRequest().body(response);
            }

            CsrGenerationResult result = hsmService.generateCsr(
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
}