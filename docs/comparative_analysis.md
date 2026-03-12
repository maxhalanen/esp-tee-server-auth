# ESP32-C6 TEE Server Authentication — Comparative Analysis
## Asymmetric vs Symmetric Cryptographic Approaches

---

## 1. Preliminary Note on Terminology

Neither approach in this project performs **encryption** — no data is made confidential. Both approaches provide **authentication** and **integrity**:

- **Authentication**: proves a message came from a specific party
- **Integrity**: proves a message was not modified in transit
- **Encryption**: hides the content of a message from observers (not implemented here)

All data — nonces, expected LED states, results — travels in plaintext over TCP. The cryptographic primitives only prove *who sent what*, not *what was sent*.

---

## 2. Hardware Foundation: The TEE

Both approaches rely on the ESP32-C6 Trusted Execution Environment. Understanding the hardware is essential to understanding what the cryptography actually protects.

The ESP32-C6 runs RISC-V at two hardware privilege levels:

| Level  | Name    | Runs                          |
|--------|---------|-------------------------------|
| M-mode | Secure (TEE) | `esp_tee.bin` — separate firmware binary |
| U-mode | Normal (REE) | Your application + all standard IDF components |

The TEE binary is independently compiled and flashed to a dedicated partition. Physical Memory Protection (PMP) registers enforce that U-mode code cannot access M-mode memory regions. Violation causes a hardware fault — there is no software bypass. Both the key material and the cryptographic operations in these projects run inside the TEE.

**Why this matters:** the security property in both approaches is not just the algorithm — it is that the *key lives in M-mode memory that the application cannot touch*. An attacker who fully controls the application layer (REE) cannot read or substitute the key.

---

## 3. Approach A — Asymmetric ECDSA-P256 (main branch)

### 3.1 Concept

A **public/private keypair** is used. The server holds the private key and is the only entity that can produce valid signatures. The device TEE holds the server's public key and can verify those signatures — but cannot produce them.

This gives **one-way authentication**: the device can verify the server, but the server cannot verify the device.

### 3.2 Algorithms

| Property          | Value                                      |
|-------------------|--------------------------------------------|
| Algorithm         | ECDSA (Elliptic Curve Digital Signature)   |
| Curve             | SECP256R1 (NIST P-256)                     |
| Key size          | 256-bit (32 bytes per coordinate)          |
| Hash function     | SHA-256                                    |
| Signature format  | Raw R \|\| S (64 bytes)                    |
| PSA constant      | `PSA_ALG_ECDSA(PSA_ALG_SHA_256)`           |
| Server key type   | Private key — PEM format, never leaves server |
| Device key type   | Public key — hardcoded in TEE M-mode `.rodata` |

**Why two coordinates (X and Y)?** The ECDSA public key is a point on the elliptic curve — a geometric coordinate pair `(X, Y)` in a 256-bit finite field. Neither coordinate alone identifies the point. The PSA API expects them concatenated in uncompressed format: `0x04 || X (32B) || Y (32B)`.

**What SHA-256 does here:** the signed object is not the message directly but its hash. `SHA-256(nonce || expected_state)` produces a fixed 32-byte digest. ECDSA signs this digest. The hash is computed in the REE (the input is not secret), then passed to the TEE service which verifies the signature against it using the hardcoded public key.

### 3.3 Key Storage

| Side   | Key          | Location                          | Protected by              |
|--------|-------------|-----------------------------------|---------------------------|
| Server | Private key | `server/server.py` (PEM constant) | Server-side security only |
| Device | Public key  | TEE M-mode `.rodata`              | PMP hardware isolation    |

The device public key is the server's public key — it is not secret. Even if an attacker dumps the TEE binary, reading the public key provides no attack capability.

### 3.4 Protocol Sequence

Phase 1 — Get Challenge:

```
title Phase 1: Get Challenge (Asymmetric)

participant Server
participant "Device (REE)" as REE
participant "Device (TEE)" as TEE

Server->REE: TCP connect
Server->REE: CMD_GET_CHALLENGE (0x00)
note over REE: esp_fill_random(32B)\nstore nonce in REE memory\ns_nonce_valid = true
REE->Server: 32-byte nonce
Server->REE: TCP close
```

Phase 2 — Verify Status:

```
title Phase 2: Verify Status (Asymmetric)

participant Server
participant "Device (REE)" as REE
participant "Device (TEE)" as TEE

note over Server: msg = nonce || expected_state\nhash = SHA-256(msg)\nsig = ECDSA_P256(hash, server_private_key)

Server->REE: TCP connect
Server->REE: [0x01][expected_state][nonce][64B ECDSA sig]
note over REE: verify nonce matches stored nonce\ns_nonce_valid = false\nbuild verify_msg = nonce || expected_state\nhash = SHA-256(verify_msg) [in REE]
REE->TEE: ecall SS_SERVER_AUTH_VERIFY_CMD(hash, sig, &valid)
note over TEE: assert M-mode\nimport server pubkey from M-mode constants\npsa_verify_hash()\ndestroy ephemeral key\nreturn valid = 1 or 0
TEE->REE: valid = 1 or 0
note over REE: if !valid: send ERROR\nread GPIO level\ncompare expected vs actual
REE->Server: "MATCH" or "MISMATCH" (plaintext string)
Server->REE: TCP close
```

### 3.5 Packet Format

```
CMD_CHECK_STATUS (98 bytes total):
┌──────┬──────────────┬──────────────────┬─────────────────────────────────────┐
│ 0x01 │ expected (1B)│   nonce (32B)    │        ECDSA sig R||S (64B)         │
└──────┴──────────────┴──────────────────┴─────────────────────────────────────┘

Response (plaintext string):
  "MATCH\n" or "MISMATCH\n" or "ERROR: ...\n"
```

---

## 4. Approach B — Symmetric HMAC-SHA256 (symmetric-hmac branch)

### 4.1 Concept

A single **shared secret key** is used by both parties. Either party can compute the same MAC given the same key and message. This gives **mutual authentication** — both the server command and the device response are authenticated.

The device TEE holds the shared key. The server holds an identical copy. Since both sides can produce valid MACs, the server cannot determine whether a valid MAC came specifically from the TEE (rather than from itself) — but in this deployment model where the server is trusted, this is acceptable.

### 4.2 Algorithms

| Property          | Value                                      |
|-------------------|--------------------------------------------|
| Algorithm         | HMAC (Hash-based Message Authentication Code) |
| Hash function     | SHA-256                                    |
| Key size          | 256-bit (32 bytes)                         |
| MAC output        | 32 bytes                                   |
| PSA constants     | `PSA_KEY_TYPE_HMAC`, `PSA_ALG_HMAC(PSA_ALG_SHA_256)` |
| PSA operations    | `psa_mac_verify()`, `psa_mac_compute()`    |
| Key type          | Symmetric — same key on both sides        |

**How HMAC works:** `HMAC-SHA256(key, msg) = SHA-256((key ⊕ opad) || SHA-256((key ⊕ ipad) || msg))`. It produces a 32-byte authentication tag. Anyone with the key can both produce and verify tags. It is significantly faster than ECDSA and requires no asymmetric math.

**Two TEE services:**
- `server_auth_verify_mac` (ID 200): verifies the server's MAC on an incoming command
- `server_auth_compute_mac` (ID 201): computes the device's MAC on the outgoing response

Both accept a 33-byte message buffer: `nonce (32B) || data_byte (1B)`. No hashing in REE — the entire MAC operation happens inside M-mode.

### 4.3 Key Storage

| Side   | Key          | Location                          | Protected by                                   |
|--------|-------------|-----------------------------------|------------------------------------------------|
| Server | Shared key  | `server/server.py` (hex constant) | Server-side security only                      |
| Device | Shared key  | TEE M-mode `.rodata`              | PMP hardware isolation + flash encryption (if enabled) |

Unlike the asymmetric approach, **the device's key is secret**. If an attacker dumps the TEE binary (physical flash access, no flash encryption), they can extract the shared key and forge both commands and responses for any device sharing that firmware.

With **flash encryption enabled**: the flash partition holding `esp_tee.bin` is encrypted using a hardware-derived key burned into eFuses. A raw flash dump yields ciphertext. This is the required mitigation.

### 4.4 Protocol Sequence

Phase 1 — Get Challenge:

```
title Phase 1: Get Challenge (Symmetric)

participant Server
participant "Device (REE)" as REE
participant "Device (TEE)" as TEE

Server->REE: TCP connect
Server->REE: CMD_GET_CHALLENGE (0x00)
note over REE: esp_fill_random(32B)\nstore nonce in REE memory\ns_nonce_valid = true
REE->Server: 32-byte nonce
Server->REE: TCP close
```

Phase 2 — Mutual Authenticated Status Check:

```
title Phase 2: Mutual Authenticated Status Check (Symmetric)

participant Server
participant "Device (REE)" as REE
participant "Device (TEE)" as TEE

note over Server: msg = nonce || expected_state\nmac = HMAC-SHA256(msg, shared_key)

Server->REE: TCP connect
Server->REE: [0x01][expected_state][nonce][32B HMAC]
note over REE: verify nonce matches stored nonce\ns_nonce_valid = false\nbuild verify_msg = nonce || expected_state
REE->TEE: ecall SS_SERVER_AUTH_VERIFY_MAC(verify_msg, mac, &valid)
note over TEE: assert M-mode\nimport shared key from M-mode constants\npsa_mac_verify()\ndestroy ephemeral key\nreturn valid = 1 or 0
TEE->REE: valid = 1 or 0
note over REE: if !valid: send ERROR\nread GPIO level\ncompare expected vs actual\nbuild resp_msg = nonce || result_byte
REE->TEE: ecall SS_SERVER_AUTH_COMPUTE_MAC(resp_msg, &resp_mac)
note over TEE: assert M-mode\nimport shared key from M-mode constants\npsa_mac_compute()\ndestroy ephemeral key\nreturn 32B MAC
TEE->REE: resp_mac (32 bytes)
REE->Server: [result_byte (1B)][resp_mac (32B)]
note over Server: recompute HMAC-SHA256(nonce || result_byte, shared_key)\nhmac.compare_digest(recv_mac, expected_mac)\nif match: confirmed from device
Server->REE: TCP close
```

### 4.5 Packet Format

```
CMD_CHECK_STATUS (66 bytes total):
┌──────┬──────────────┬──────────────────┬───────────────────┐
│ 0x01 │ expected (1B)│   nonce (32B)    │  HMAC-SHA256 (32B)│
└──────┴──────────────┴──────────────────┴───────────────────┘

Response (33 bytes binary):
┌───────────────┬─────────────────────────────────────────────┐
│ result (1B)   │           HMAC-SHA256 (32B)                 │
│ 0x01=MATCH    │  HMAC-SHA256(nonce || result, shared_key)   │
│ 0x00=MISMATCH │                                             │
└───────────────┴─────────────────────────────────────────────┘
```

---

## 5. Side-by-Side Comparison

### 5.1 Authentication Properties

| Property                            | Asymmetric (ECDSA) | Symmetric (HMAC)   |
|-------------------------------------|--------------------|--------------------|
| Device verifies server              | Yes                | Yes                |
| Server verifies device response     | No                 | Yes                |
| Server can forge device response    | N/A                | Yes (knows key)    |
| One device compromise affects others| No                 | Yes (shared firmware key) |
| True non-repudiation                | Yes                | No                 |

### 5.2 Cryptographic Properties

| Property              | Asymmetric (ECDSA-P256) | Symmetric (HMAC-SHA256) |
|-----------------------|-------------------------|-------------------------|
| Key operations in TEE | Verify (psa_verify_hash) | Verify + Compute        |
| Hash computed in      | REE (passed to TEE)     | TEE (internally)        |
| TEE service calls     | 1 per exchange          | 2 per exchange          |
| Signature/MAC size    | 64 bytes                | 32 bytes                |
| Packet size           | 98 bytes                | 66 bytes                |
| Computation cost      | High (elliptic curve)   | Low (hash only)         |
| Key distribution      | Easy (public key)       | Hard (secret must be shared securely) |

### 5.3 Security Properties

| Property                         | Asymmetric (ECDSA) | Symmetric (HMAC)              |
|----------------------------------|--------------------|-------------------------------|
| Device key is secret             | No (public key)    | Yes                           |
| Flash dump exposes key           | No (public key)    | Yes (without flash encryption)|
| Flash encryption required        | No                 | Yes for full security         |
| Key rotation requires            | Reflash            | Reflash                       |
| Per-device unique keys possible  | Yes (generate per device) | Yes (unique key per device)  |

---

## 6. Attack Surface Analysis

### 6.1 Attacks Closed by Both Approaches

**Key substitution by compromised REE:**
An attacker with full REE control cannot swap the key used for verification — it lives in M-mode `.rodata` and is inaccessible from U-mode. Any attempt to read or write M-mode addresses from U-mode triggers a hardware fault enforced by PMP registers. This is the primary security property the TEE provides in both approaches.

**Forged commands (no key knowledge):**
Without the server's private key (asymmetric) or shared key (symmetric), an attacker cannot produce a valid signature or MAC. Commands with invalid authentication tags are rejected by the TEE service before any LED comparison occurs.

**Replay attacks:**
Each exchange uses a fresh 32-byte nonce generated by `esp_fill_random()`. The nonce is stored and invalidated on first use. A recorded valid exchange cannot be replayed — the nonce comparison (`memcmp`) in the REE will fail.

### 6.2 Residual Attack Surface (Both Approaches)

**Compromised REE — nonce lifecycle:**
The nonce is generated and stored in REE memory (`s_pending_nonce`, `s_nonce_valid`). A fully compromised REE can:
- Restore a consumed nonce and set `s_nonce_valid = true`
- Replay a previously captured exchange

Mitigation: move nonce generation and storage into the TEE. However, since the REE still controls TCP transport (the network stack cannot run in TEE), the REE forwards the nonce to the server and could substitute it, so TEE-side nonce storage eliminates the restoration attack but not a man-in-the-middle attack by a fully compromised REE.

**No channel encryption:**
All data including nonces, expected states, and results are plaintext on the wire. A passive network observer sees the full exchange. The authentication provides integrity and origin verification, not confidentiality.

Mitigation: wrap the TCP connection in TLS. The mbedTLS library is available in IDF and can be used in the REE application layer.

### 6.3 Asymmetric-Specific Attack Surface

**None beyond the above.** The server's public key hardcoded in M-mode is not secret — reading it from a firmware dump provides zero attack capability. The private key never touches the device.

### 6.4 Symmetric-Specific Attack Surface

**Physical flash dump (without flash encryption):**
The shared key is secret. `esp_tee.bin` is stored in a flash partition. Without flash encryption, attaching to the SPI flash bus and dumping the binary directly extracts the key in plaintext. With the key, an attacker can:
- Forge valid server commands to any device sharing that firmware
- Forge valid device responses

Mitigation: enable flash encryption (see Section 6.5).

**Single key shared across all devices:**
If the symmetric key is hardcoded in firmware, all devices running the same firmware share the same key. Compromising one device (extracting the key via flash dump) compromises all devices.

Mitigation: provision a unique key per device during manufacturing using TEE secure storage, rather than hardcoding in firmware.

**Server-side key exposure:**
The server holds the shared key in `server.py`. If the server is compromised, the attacker can forge device responses. In the asymmetric approach, a compromised server exposes only the ability to forge server commands — not device responses.

### 6.5 Flash Encryption (Symmetric Approach — Production Requirement)

Flash encryption is a hardware feature of the ESP32-C6 that encrypts all flash partitions — including the TEE partition holding `esp_tee.bin` — using an AES-256 key derived from hardware eFuses. A raw flash dump yields ciphertext only.

**How it works on ESP32-C6:**
On first boot with flash encryption enabled, the device generates a random AES-256 key from its hardware RNG, burns it into eFuse (`KEY_PURPOSE_XTS_AES_256`), and encrypts the flash contents in-place. The key never leaves the chip. The host never has access to it.

**Two modes:**

| Mode        | eFuse state       | Can be disabled | UART download | Subsequent flashing |
|-------------|-------------------|-----------------|---------------|---------------------|
| Development | Reversible (×3)   | Yes (limited)   | Allowed       | `idf.py encrypted-flash` |
| Release     | Permanent         | No              | Disabled      | Encrypted OTA only  |

Development mode is appropriate for testing and iteration. Release mode is for production deployment.

**Impact on development workflow:**
Once flash encryption is enabled, `idf.py flash` (plaintext) no longer works. All subsequent flashes must use `idf.py encrypted-flash`, which operates over UART and is slower. If a device in Release mode is bricked mid-flash, it is unrecoverable — the key is in eFuse and the flash is corrupt.

**Status in this project:**
Flash encryption is **not enabled** in the current `sdkconfig.defaults` of the `symmetric-hmac` branch. The symmetric shared key is unprotected against physical flash extraction on the dev board. This is intentional for development convenience. For any production deployment of the symmetric approach, flash encryption in at minimum Development mode is required for the security model to hold.

To enable for production, add to `sdkconfig.defaults`:
```
CONFIG_SECURE_FLASH_ENC_ENABLED=y
CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT=y   # or RELEASE for production
```

---

## 7. What the TEE Does and Does Not Protect

| Claim                                            | Asymmetric | Symmetric |
|--------------------------------------------------|------------|-----------|
| Key cannot be read by REE software               | Yes (public key — irrelevant) | Yes |
| Key cannot be modified by REE software           | Yes        | Yes       |
| Key cannot be extracted by physical flash dump   | Yes (public key) | Only with flash encryption |
| Verification logic cannot be bypassed by REE     | Yes        | Yes       |
| Nonce generation is TEE-controlled               | No         | No        |
| Network transport is TEE-controlled              | No         | No        |
| Full protocol isolation from REE                 | No         | No        |

The TEE provides a **tamper-proof trust anchor for the key and the verification logic**. It does not provide full protocol isolation because the network stack, nonce management, and GPIO reading all run in the REE.

---

## 8. Algorithm Alternatives

### Signature/MAC alternatives supported by PSA Crypto in the TEE

| Algorithm      | Type        | PSA Constant                        | Key Size | Output | Notes                          |
|---------------|-------------|-------------------------------------|----------|--------|--------------------------------|
| ECDSA-P256    | Asymmetric  | `PSA_ALG_ECDSA(PSA_ALG_SHA_256)`    | 256-bit  | 64B    | Current asymmetric impl        |
| ECDSA-P384    | Asymmetric  | `PSA_ALG_ECDSA(PSA_ALG_SHA_384)`    | 384-bit  | 96B    | Higher security margin         |
| Ed25519       | Asymmetric  | `PSA_ALG_PURE_EDDSA`                | 256-bit  | 64B    | Deterministic, faster verify, 32B pubkey |
| RSA-PSS-2048  | Asymmetric  | `PSA_ALG_RSA_PSS(PSA_ALG_SHA_256)`  | 2048-bit | 256B   | Large key/sig, widely supported |
| HMAC-SHA256   | Symmetric   | `PSA_ALG_HMAC(PSA_ALG_SHA_256)`     | 256-bit  | 32B    | Current symmetric impl         |
| HMAC-SHA384   | Symmetric   | `PSA_ALG_HMAC(PSA_ALG_SHA_384)`     | 384-bit  | 48B    | Larger output, marginal benefit |
| AES-CMAC      | Symmetric   | `PSA_ALG_CMAC`                      | 128-bit  | 16B    | Hardware-accelerated on ESP32  |

### For genuine mutual asymmetric authentication

The symmetric approach achieves mutual authentication but at the cost of the server being able to forge device responses. True mutual asymmetric authentication — where neither party can forge the other's messages — requires two independent keypairs:

- **Server → Device**: server private key signs commands; device TEE holds server public key *(current asymmetric approach)*
- **Device → Server**: device private key (in TEE secure storage) signs responses; server holds device public key

This is the pattern used in mTLS and full device attestation systems. It is more complex (requires per-device key provisioning) but provides non-repudiation in both directions.

---

## 9. Summary

| Factor                    | Asymmetric (ECDSA-P256)            | Symmetric (HMAC-SHA256)               |
|---------------------------|-------------------------------------|---------------------------------------|
| **Authentication**        | Server → Device only               | Mutual (both directions)              |
| **Key secrecy on device** | Not required (public key)          | Required (flash encryption needed)    |
| **Key distribution**      | Simple (public key is public)      | Complex (secret must be shared)       |
| **Computation cost**      | Higher (elliptic curve math)       | Lower (hash operations only)          |
| **Packet size**           | 98 bytes                           | 66 bytes                              |
| **Non-repudiation**       | Yes — only server can sign         | No — server can forge device response |
| **TEE services**          | 1                                  | 2                                     |
| **Suitable when**         | Server identity is the threat model | Mutual auth needed, server is trusted |
