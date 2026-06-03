# payshield-crypto-client — API Specification

A Spring Boot auto-configuration library that exposes Thales payShield 10K HSM
cryptographic operations over TCP. The library is **stateless** — it issues commands
to the HSM and returns results. The caller is responsible for persisting any key
material between calls.

---

## Table of Contents

1. [Dependency](#1-dependency)
2. [Configuration](#2-configuration)
3. [LMK Modes](#3-lmk-modes)
4. [Auto-wired Bean](#4-auto-wired-bean)
5. [API Reference](#5-api-reference)
   - [generateKeyPair](#51-generatekeypair)
   - [signMessage](#52-signmessage)
   - [verifySignature](#53-verifysignature)
   - [generateCsr / generateCsrPem](#54-generatecsr--generatecsrpem)
   - [importPublicKey](#55-importpublickey)
   - [Diagnostics](#56-diagnostics)
   - [Utility](#57-utility)
6. [Return Types](#6-return-types)
7. [Error Handling](#7-error-handling)
8. [Typical Flows](#8-typical-flows)
9. [Hash & Padding Identifiers](#9-hash--padding-identifiers)
10. [Threading](#10-threading)

---

## 1. Dependency

```xml
<dependency>
    <groupId>my.com.kambiz.hsm</groupId>
    <artifactId>payshield-crypto-client</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

---

## 2. Configuration

Add to your `application.yml` (or `application.properties`). Only `payshield.host`
is required — all other properties have defaults.

```yaml
payshield:
  # --- Connection ---
  host: 192.168.1.100          # HSM IP address (REQUIRED)
  port: 1501                   # Variant LMK port (default: 1501)
  port-key-block: 1502         # Key Block LMK port (default: 1502)
  lmk-mode: keyblock           # "variant" or "keyblock" (default: keyblock)
  connect-timeout-ms: 5000     # TCP connect timeout in ms (default: 5000)
  read-timeout-ms: 10000       # TCP read timeout in ms (default: 10000)
  length-prefix-enabled: true  # 2-byte length framing (default: true)
  header-length: 4             # Message header length: 0, 2, or 4 (default: 4)

  # --- Connection Pool ---
  pool-max-total: 5            # Max total TCP connections (default: 5)
  pool-max-idle: 3             # Max idle connections (default: 3)
  pool-min-idle: 1             # Min idle connections (default: 1)

  # --- Cryptographic Defaults ---
  default-modulus-length: 2048 # Default RSA key size in bits (default: 2048)
  default-hash-id: "06"        # Default hash: SHA-256 (default: "06")
  default-sig-id: "01"         # Signature algorithm: RSA (default: "01")
  default-pad-mode: "01"       # Padding: PKCS#1 v1.5 (default: "01")

  # --- Key Block LMK specific (only relevant when lmk-mode=keyblock) ---
  key-block-mode-of-use: S     # 'S'=Sign only, 'D'=Decrypt, 'N'=No restriction
  key-block-key-version: "00"  # Key version number "00"-"99" (default: "00")
  key-block-exportability: N   # 'N'=Non-exportable, 'S'=Exportable (default: N)
```

The active HSM port is chosen automatically based on `lmk-mode`:
- `variant`  → `payshield.port` (1501)
- `keyblock` → `payshield.port-key-block` (1502)

---

## 3. LMK Modes

| Mode | LMK Type | Port | Private Key Format | Use Case |
|------|----------|------|--------------------|----------|
| `variant` | 3DES Variant LMK | 1501 | Raw LMK-encrypted blob | Legacy / backward compat |
| `keyblock` | AES Key Block LMK | 1502 | TR-31 key block, `S`-prefixed | PCI-compliant, recommended |

The mode controls:
- Which TCP port is connected
- How EI, EO, EW, EY commands are constructed
- The format of the private key blob returned by `generateKeyPair()`

`KeyGenerationResult.isKeyBlock()` reflects which format was used, so callers
can store this flag alongside the key blob and pass it correctly to `signMessage()`.

---

## 4. Auto-wired Bean

The library registers a single Spring bean when `payshield.host` is set:

```java
@Autowired
HsmCryptoService hsmCryptoService;
```

No additional `@Configuration` or `@Bean` declarations are needed. Override
`PayShieldConnectionPool` or `HsmCryptoService` with your own `@Bean` to
customise behaviour.

---

## 5. API Reference

All methods are on `my.com.kambiz.hsm.service.HsmCryptoService`.

### 5.1 `generateKeyPair`

Generate an RSA key pair inside the HSM. The private key never leaves the HSM
in plaintext — it is returned encrypted under the LMK.

```java
KeyGenerationResult generateKeyPair(int modulusBits)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `modulusBits` | `int` | RSA modulus length. Supported: `1024`, `2048`, `4096` (Key Block supports up to 4096; Variant is typically capped at 2048) |

**Returns:** [`KeyGenerationResult`](#keyGenerationResult)

**Throws:** `PayShieldException` on HSM error.

---

### 5.2 `signMessage`

Sign a message with the RSA private key. Two overloads — use the short form to
apply the defaults configured in `application.yml`.

```java
// Uses default hash and padding from configuration
SigningResult signMessage(byte[] messageData,
                          byte[] privateKeyBlob,
                          boolean isKeyBlock)

// Explicit hash and padding
SigningResult signMessage(byte[] messageData,
                          byte[] privateKeyBlob,
                          boolean isKeyBlock,
                          String hashId,
                          String padMode)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `messageData` | `byte[]` | Raw message bytes to sign |
| `privateKeyBlob` | `byte[]` | `KeyGenerationResult.getPrivateKeyLmkEncrypted()` |
| `isKeyBlock` | `boolean` | `KeyGenerationResult.isKeyBlock()` |
| `hashId` | `String` | Hash algorithm ID — see [§9](#9-hash--padding-identifiers) |
| `padMode` | `String` | Padding mode ID — see [§9](#9-hash--padding-identifiers) |

**Returns:** [`SigningResult`](#signingresult)

**Throws:** `PayShieldException` on HSM error.

---

### 5.3 `verifySignature`

Verify an RSA digital signature. Internally performs EO (import public key) then
EY (verify). Both steps are transparent to the caller.

```java
// Uses default hash and padding from configuration
VerificationResult verifySignature(byte[] signature,
                                   byte[] messageData,
                                   byte[] publicKeyDer)

// Explicit hash and padding
VerificationResult verifySignature(byte[] signature,
                                   byte[] messageData,
                                   byte[] publicKeyDer,
                                   String hashId,
                                   String padMode)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `signature` | `byte[]` | Signature bytes from `SigningResult.getSignature()` |
| `messageData` | `byte[]` | Original message bytes that were signed |
| `publicKeyDer` | `byte[]` | DER-encoded public key from `KeyGenerationResult.getPublicKeyDer()` |
| `hashId` | `String` | Must match the hash used when signing |
| `padMode` | `String` | Must match the padding used when signing |

**Returns:** [`VerificationResult`](#verificationresult)

**Throws:** `PayShieldException` on HSM communication error.
Note: a *signature mismatch* does **not** throw — it returns `VerificationResult.isValid() == false`.

---

### 5.4 `generateCsr` / `generateCsrPem`

Generate a PKCS#10 Certificate Signing Request via the HSM QE command.
**Requires Key Block LMK mode** (`lmk-mode=keyblock`). The private key is used
inside the HSM to sign the CSR — it never leaves the HSM boundary.

```java
// Full control over output format
CsrGenerationResult generateCsr(byte[] publicKeyDer,
                                 byte[] privateKeyBlock,
                                 String commonName,
                                 String organization,
                                 String orgUnit,
                                 String locality,
                                 String state,
                                 String country,
                                 boolean pemOutput)

// Convenience — always returns PEM
CsrGenerationResult generateCsrPem(byte[] publicKeyDer,
                                    byte[] privateKeyBlock,
                                    String commonName,
                                    String organization,
                                    String orgUnit,
                                    String locality,
                                    String state,
                                    String country)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `publicKeyDer` | `byte[]` | `KeyGenerationResult.getPublicKeyDer()` |
| `privateKeyBlock` | `byte[]` | `KeyGenerationResult.getPrivateKeyLmkEncrypted()` — must be Key Block (`S`-prefix) |
| `commonName` | `String` | CN field (e.g. `"my-service.example.com"`) |
| `organization` | `String` | O field |
| `orgUnit` | `String` | OU field |
| `locality` | `String` | L field |
| `state` | `String` | ST field |
| `country` | `String` | C field — **must be exactly 2 characters** (ISO 3166-1 alpha-2, e.g. `"MY"`) |
| `pemOutput` | `boolean` | `true` = PEM (Base64), `false` = Hex DER |

**Returns:** [`CsrGenerationResult`](#csrgenerationresult)

**Throws:** `PayShieldException` on HSM error.

---

### 5.5 `importPublicKey`

Import a DER-encoded RSA public key into the HSM (EO command). Returns the
HSM-protected form of the key. Useful when you need to verify signatures using
a public key from an external source.

```java
PublicKeyImportResult importPublicKey(byte[] publicKeyDer)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `publicKeyDer` | `byte[]` | DER-encoded RSA public key |

**Returns:** [`PublicKeyImportResult`](#publickeyimportresult)

**Throws:** `PayShieldException` on HSM error.

> Note: `verifySignature()` calls this internally. You only need `importPublicKey()`
> directly if you want to reuse an imported key across multiple verification calls
> without re-importing it each time.

---

### 5.6 Diagnostics

These are static utility methods on `DiagnosticCommands`. They require an
`HsmCryptoService` to send the raw command bytes.

```java
// NC — Perform Diagnostics (no auth required, safe for health checks)
byte[] ncCmd = DiagnosticCommands.buildNC(header);
byte[] ncResp = hsmCryptoService.executeRaw(ncCmd);
Map<String, String> info = DiagnosticCommands.parseNCResponse(ncResp, headerLength);
// info keys: status, lmkCheckValue, firmwareNumber, errorCode

// NO — HSM Status
byte[] noCmd = DiagnosticCommands.buildNO(header, "00");
byte[] noResp = hsmCryptoService.executeRaw(noCmd);
Map<String, String> status = DiagnosticCommands.parseNOResponse(noResp, headerLength);
// status keys: status, ioBufferSize, ethernetType, numTcpSockets, firmwareNumber
```

The `header` string and `headerLength` int should match `payshield.header-length`
in your configuration (default `"0000"` and `4`).

---

### 5.7 Utility

```java
// Active LMK mode
LmkMode mode = hsmCryptoService.getLmkMode(); // LmkMode.VARIANT or LmkMode.KEYBLOCK

// Connection pool stats (for monitoring/health endpoints)
String stats = hsmCryptoService.getPoolStats(); // "active=1, idle=2, waiting=0"

// Send a raw command byte array and get the raw response back
// Use only for diagnostics or commands not covered by the service
byte[] response = hsmCryptoService.executeRaw(byte[] command);
```

---

## 6. Return Types

### `KeyGenerationResult`

| Method | Type | Description |
|--------|------|-------------|
| `getPublicKeyDer()` | `byte[]` | DER-encoded RSA public key |
| `getPublicKeyHex()` | `String` | Hex string of the DER public key |
| `getPrivateKeyLmkEncrypted()` | `byte[]` | Private key encrypted under LMK (Key Block: `S`-prefixed; Variant: raw blob) |
| `getPrivateKeyHex()` | `String` | Hex string of the encrypted private key |
| `getPrivateKeyLength()` | `int` | Byte length of the encrypted private key |
| `getModulusLengthBits()` | `int` | RSA modulus size (e.g. 2048) |
| `isKeyBlock()` | `boolean` | `true` if Key Block LMK format |
| `getLmkScheme()` | `String` | Human-readable scheme description |

**Important:** Store both `getPrivateKeyLmkEncrypted()` and `isKeyBlock()` together.
You will need both when calling `signMessage()` or `generateCsr()`.

---

### `SigningResult`

| Method | Type | Description |
|--------|------|-------------|
| `getSignature()` | `byte[]` | Raw signature bytes |
| `getSignatureHex()` | `String` | Hex string of the signature |
| `getSignatureLength()` | `int` | Byte length of the signature |
| `getHashAlgorithm()` | `String` | Human-readable hash name (e.g. `"SHA-256"`) |
| `getPadMode()` | `String` | Human-readable padding name (e.g. `"PKCS#1 v1.5"`) |

---

### `VerificationResult`

| Method | Type | Description |
|--------|------|-------------|
| `isValid()` | `boolean` | `true` if the signature is valid |
| `getErrorCode()` | `String` | HSM error code (`"00"` = valid) |
| `getErrorDescription()` | `String` | Human-readable description |
| `getRawResponseHex()` | `String` | Full raw HSM response in hex (for debugging) |

---

### `CsrGenerationResult`

| Method | Type | Description |
|--------|------|-------------|
| `getCsrData()` | `String` | CSR content — PEM string or Hex DER depending on `pemOutput` |
| `getCsrLength()` | `int` | Character length of the CSR data |
| `isPem()` | `boolean` | `true` if the data is in PEM format |
| `getFormattedPem()` | `String` | PEM with proper 64-char line breaks (safe to call even if already formatted) |

---

### `PublicKeyImportResult`

Returned by `importPublicKey()`. Normally you do not need to use this directly —
it is consumed internally by `verifySignature()`.

| Method | Type | Description |
|--------|------|-------------|
| `isKeyBlock()` | `boolean` | `true` for Key Block mode result |
| `getMac()` | `byte[]` | 4-byte MAC (Variant mode only; `null` in Key Block mode) |
| `getMacHex()` | `String` | Hex MAC or `"(embedded in key block)"` |
| `getPublicKeyDer()` | `byte[]` | DER public key (Variant mode only; `null` in Key Block mode) |
| `getPublicKeyBlock()` | `byte[]` | Full `S`-prefixed key block (Key Block mode only; `null` in Variant mode) |

---

## 7. Error Handling

All failures throw `my.com.kambiz.hsm.exception.PayShieldException` (unchecked).

```java
try {
    SigningResult result = hsmCryptoService.signMessage(data, privKey, isKeyBlock);
} catch (PayShieldException e) {
    String cmd   = e.getCommandCode();   // e.g. "EW"
    String code  = e.getErrorCode();     // e.g. "12"
    String msg   = e.getMessage();       // full description
}
```

Common error codes:

| Code | Meaning |
|------|---------|
| `00` | No error |
| `01` | Signature verification failure |
| `12` | User storage not available |
| `17` | HSM not in Authorized state |
| `30` | Data length invalid |
| `68` | Command not available / disabled |
| `75` | HSM in wrong LMK mode |
| `76` | RSA key generation failure |
| `91` | Feature not licensed |
| `A1` | Incompatible LMK scheme |
| `A2` | Incompatible key block LMK identifier |

---

## 8. Typical Flows

### Flow 1 — Key Block: generate, sign, verify

```java
// 1. Generate RSA-2048 key pair
KeyGenerationResult keyPair = hsmCryptoService.generateKeyPair(2048);

// Persist these — the library does not store them
byte[] publicKeyDer      = keyPair.getPublicKeyDer();
byte[] privateKeyBlob    = keyPair.getPrivateKeyLmkEncrypted();
boolean isKeyBlock       = keyPair.isKeyBlock();

// 2. Sign
byte[] message = "Hello, HSM".getBytes(StandardCharsets.UTF_8);
SigningResult signing = hsmCryptoService.signMessage(message, privateKeyBlob, isKeyBlock);
byte[] signature = signing.getSignature();

// 3. Verify
VerificationResult result = hsmCryptoService.verifySignature(signature, message, publicKeyDer);
if (result.isValid()) {
    // signature OK
} else {
    // result.getErrorDescription() explains why
}
```

---

### Flow 2 — Key Block: generate key pair, then generate CSR

```java
// 1. Generate key pair (must be Key Block mode)
KeyGenerationResult keyPair = hsmCryptoService.generateKeyPair(2048);

// 2. Generate CSR — HSM signs it internally, private key never exposed
CsrGenerationResult csr = hsmCryptoService.generateCsrPem(
    keyPair.getPublicKeyDer(),
    keyPair.getPrivateKeyLmkEncrypted(),
    "my-service.example.com",  // CN
    "My Organisation",         // O
    "Engineering",             // OU
    "Kuala Lumpur",            // L
    "Wilayah Persekutuan",     // ST
    "MY"                       // C — must be 2 chars
);

String pemCsr = csr.getFormattedPem();
// Submit pemCsr to your CA
```

---

### Flow 3 — Sign with explicit SHA-512 and PSS padding

```java
SigningResult result = hsmCryptoService.signMessage(
    messageBytes,
    privateKeyBlob,
    isKeyBlock,
    "08",   // SHA-512
    "04"    // PSS
);
```

---

### Flow 4 — Health check

```java
String header = "0000"; // match payshield.header-length
int headerLen = 4;

byte[] ncCmd  = DiagnosticCommands.buildNC(header);
byte[] ncResp = hsmCryptoService.executeRaw(ncCmd);
Map<String, String> diag = DiagnosticCommands.parseNCResponse(ncResp, headerLen);

if ("OK".equals(diag.get("status"))) {
    log.info("HSM OK — firmware={}, lmkCheck={}",
        diag.get("firmwareNumber"), diag.get("lmkCheckValue"));
}
```

---

## 9. Hash & Padding Identifiers

### Hash Algorithm IDs (`hashId`)

| ID | Algorithm |
|----|-----------|
| `"01"` | SHA-1 |
| `"02"` | MD5 |
| `"05"` | SHA-224 |
| `"06"` | SHA-256 *(default)* |
| `"07"` | SHA-384 |
| `"08"` | SHA-512 |
| `"04"` | No hash (raw data passed directly) |

### Padding Mode IDs (`padMode`)

| ID | Mode |
|----|------|
| `"01"` | PKCS#1 v1.5 *(default)* |
| `"02"` | ANSI X9.31 |
| `"03"` | ISO 9796 |
| `"04"` | PSS (RSASSA-PSS) |

---

## 10. Threading

`HsmCryptoService` is a stateless Spring singleton — **safe for concurrent use**.
The underlying connection pool (`GenericObjectPool`) serialises per-connection
access automatically; each concurrent call borrows its own TCP connection.

Pool sizing guidance:

```yaml
payshield:
  pool-max-total: 10   # set to peak expected concurrent HSM calls
  pool-max-idle: 5
  pool-min-idle: 2
```

If all connections are in use, callers block until one is returned to the pool.
