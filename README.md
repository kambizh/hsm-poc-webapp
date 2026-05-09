# hsm-poc-webapp

A lightweight Spring Boot web application used to demonstrate and validate HSM-based cryptographic operations using the `payshield-crypto-client` library.

## Purpose

This application is the **Proof of Concept (POC) UI** for Thales payShield 10K integration. It exercises the crypto client through REST APIs and a simple HTML dashboard so you can confirm end-to-end behavior in the lab.

It tracks the **`feature/aes-keyblock-lmk`** work in the companion library: **Variant LMK (3DES, port 1501)** versus **AES Key Block LMK (port 1502)**.

## How to start

```bash
nohup java -jar hsm-poc-webapp-1.0.0-SNAPSHOT.jar &
```

Alternatively run from Maven in the repo: `mvn spring-boot:run` (with the client module installed or on the reactor classpath as in your layout).

## Configuration (LMK mode and ports)

In `src/main/resources/application.properties`:

- **`payshield.lmk-mode`** — `variant` or `keyblock`. Selects command wire format and parsing in the client.
- **`payshield.port`** — Variant host command port (commonly **1501**).
- **`payshield.port-key-block`** — Key Block host command port (commonly **1502**).

Key Block–specific defaults used when importing/generating material in keyblock mode:

- `payshield.key-block-mode-of-use` (e.g. `S` = Sign)
- `payshield.key-block-key-version` (e.g. `00`)
- `payshield.key-block-exportability` (e.g. `N` = Non-exportable)

Crypto defaults (e.g. SHA-256 `06`, PKCS#1 v1.5 `01`) are aligned with typical PayNet RPP lab settings—adjust per your integration guide.

After changing **`payshield.host`** or **`payshield.lmk-mode`**, restart the application so all connections use the new target.

## Features

- **RSA key pair generation** (EI) with API responses that include **`lmkMode`**, **`lmkScheme`**, and **`isKeyBlock`**
- **Sign** (EW) and **verify** (EO + EY) with step-by-step **hsmFlow** text that differs for Variant vs Key Block material
- **PKCS#10 CSR generation** (QE) from the last generated key pair — **only in Key Block LMK mode** (Variant-generated keys are rejected by the service)
- **Diagnostics** (NC) and **HSM status** (NO)
- **State** endpoint summarizing whether a key pair/signature exists and the current key material type
- Simple **browser UI** (Thymeleaf `index.html`) for the same flows

JSON bodies for sign/verify default hash ID **`06`** (SHA-256) unless overridden.

## API overview (representative routes)

| Method | Path | Role |
|--------|------|------|
| `POST` | `/api/generate-key` | Generate key pair |
| `POST` | `/api/sign` | Sign message |
| `POST` | `/api/verify` | Verify signature |
| `POST` | `/api/generate-csr` | Build CSR (after key generation) |
| `GET` | `/api/state` | Last key/signature hints + **`lmkMode`** / **`isKeyBlock`** |
| `GET` | `/api/diagnostics` | NC diagnostics |
| `GET` | `/api/hsm-status` | NO status |

Many responses echo **`lmkMode`** so the UI and integrators can see which LMK architecture was active for the request.

## Related module

Install or build **`payshield-crypto-client`** first when packaging this application; see that module’s README for command-level detail and **`LmkMode`** behavior.

