# ESP32-C6 TEE Server Authentication — Protocol & Technical Reference

## Overview

This project implements a **server-to-device authentication protocol** on the ESP32-C6. The device will only act on commands that carry a valid cryptographic signature from a specific trusted server. The trusted server's identity is anchored inside the device's **Trusted Execution Environment (TEE)**, where it cannot be read or modified by any software running in the normal application environment.

The specific demonstration has the device auto-blinking an LED and the server asserting what the LED state *should* be. The device verifies the server's claim is signed by the legitimate server, then compares it against the actual GPIO level, responding `MATCH` or `MISMATCH`.

---

## 1. Background: TEE Architecture on ESP32-C6

The ESP32-C6 runs RISC-V with two hardware privilege levels:

| Level  | Name   | Also Called | Runs              |
|--------|--------|-------------|-------------------|
| M-mode | Secure | TEE         | TEE firmware      |
| U-mode | Normal | REE         | Your application  |

**Two separate binaries are flashed:**
- `esp_tee.bin` — TEE firmware, compiled from `components/esp_tee/subproject/`. Contains its own copy of mbedTLS and PSA Crypto, initialized at TEE startup via `psa_crypto_init()`. Runs in M-mode.
- The main application binary — your `app_main.c` and all standard IDF components. Runs in U-mode.

These binaries are **independently compiled** using CMake's `externalproject_add()`. The TEE binary lives in dedicated flash and SRAM partitions enforced by PMP (Physical Memory Protection) registers. U-mode code that attempts to access M-mode memory causes a hardware fault — there is no software bypass.

**Relevant IDF source references:**
- `components/esp_tee/CMakeLists.txt` line 6: *"headers & sources here are compiled into the app, not the esp_tee binary"*
- `components/esp_tee/subproject/CMakeLists.txt` lines 27–32: mbedtls listed as a TEE subproject component
- `components/esp_tee/subproject/main/core/esp_tee_init.c` lines 159–164: `psa_crypto_init()` called at M-mode startup
- `docs/en/security/tee/tee-advanced.rst`: full isolation mechanism documentation

---

## 2. The Custom TEE Service

The core of this project is a **custom secure service** registered with the TEE: `server_auth_verify_cmd`.

### What it does

The service runs entirely in M-mode. It holds the server's ECDSA-P256 public key as compile-time constants in M-mode `.rodata`:

```c
// components/server_auth_service/server_auth_service.c
static const uint8_t SERVER_PUBKEY_X[32] = { 0x1C, 0x62, ... };
static const uint8_t SERVER_PUBKEY_Y[32] = { 0x67, 0xF4, ... };
```

When called, it:
1. Asserts it is running in M-mode (`esp_cpu_get_curr_privilege_level()`)
2. Constructs the uncompressed public key point: `0x04 || X || Y` (65 bytes)
3. Imports the key into PSA Crypto (ephemeral, in-memory only, never stored)
4. Calls `psa_verify_hash()` against the ECDSA-P256 signature received from the server
5. Destroys the ephemeral key
6. Returns 1 (valid) or 0 (invalid) through the output pointer

### Why the public key is split into X and Y

ECDSA-P256 (also called secp256r1) is an elliptic curve. A public key on this curve is a **point** — a pair of coordinates `(X, Y)` in a 256-bit finite field. Each coordinate is 32 bytes, giving 64 bytes total for the key. The PSA Crypto API requires the uncompressed point format: `0x04 || X || Y` (65 bytes). The X and Y are stored separately for clarity; they are concatenated before use.

### Service registration

The service is registered via a YAML descriptor table:

```yaml
# components/server_auth_service/sec_srv_tbl_server_auth.yml
secure_services:
  - family: server_auth
    entries:
      - id: 200
        type: custom
        function: server_auth_verify_cmd
        args: 3
```

This is processed at build time (same pattern as ESP-IDF's own built-in services). The service gets ID `SS_SERVER_AUTH_VERIFY_CMD = 200` and is registered in the TEE's secure service dispatch table. The REE calls it via:

```c
esp_tee_service_call_with_noniram_intr_disabled(4, SS_SERVER_AUTH_VERIFY_CMD, hash, sig, &valid);
```

The `4` is the total argument count (service ID + 3 data args). Non-IRAM interrupts are disabled during the M-mode call to prevent interrupt handlers from observing partially-transferred state across the privilege boundary.

---

## 3. Cryptographic Primitives

### Algorithm: ECDSA-P256 with SHA-256

| Property        | Value                        |
|----------------|------------------------------|
| Curve           | SECP256R1 (NIST P-256)       |
| Key size        | 256 bits                     |
| Hash            | SHA-256                      |
| Signature size  | 64 bytes (R \|\| S, raw)      |
| PSA algorithm   | `PSA_ALG_ECDSA(PSA_ALG_SHA_256)` |
| Key type        | `PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1)` |

**Why ECDSA-P256?**
It is the curve supported by both ESP-IDF's PSA/mbedTLS TEE build and Python's `cryptography` library without any extra configuration. P-256 provides ~128-bit security and is the most widely deployed elliptic curve.

### Where each operation runs

| Operation                          | Runs in | Justification                              |
|------------------------------------|---------|--------------------------------------------|
| Generate nonce                     | REE     | `esp_fill_random()` — output is not secret |
| Compute SHA-256(nonce \|\| state)   | REE     | Hash input is not secret                   |
| ECDSA signature (server side)      | Server  | Python `cryptography` library              |
| ECDSA verification                 | TEE (M-mode) | Public key lives here; PSA runs here  |
| Compare expected vs actual state   | REE     | GPIO read, no secret involved              |

The hash is computed in the REE and passed to the TEE service. This is acceptable because the hash input (nonce + expected_state) is not secret — the security property is not confidentiality of the hash, but rather that the *verification key cannot be substituted* by REE code.

---

## 4. Protocol: Step-by-Step Control Flow

### Phase 1 — Get Challenge Nonce

```
title Phase 1: Get Challenge Nonce

participant Server
participant "Device (REE)" as REE
participant "Device (TEE)" as TEE

Server->REE: TCP connect
Server->REE: CMD_GET_CHALLENGE (0x00)
note over REE: esp_fill_random(32B)\nstore as s_pending_nonce\ns_nonce_valid = true
REE->Server: 32-byte nonce
Server->REE: TCP close
```

### Phase 2 — Sign and Send Check

```
title Phase 2: Sign and Send Check

participant Server
participant "Device (REE)" as REE
participant "Device (TEE)" as TEE

note over Server: msg = nonce || expected_state\nsig = ECDSA_P256_SHA256(msg, privkey)

Server->REE: TCP connect
Server->REE: [0x01][expected_state][nonce][sig]
note over REE: verify nonce matches s_pending_nonce\ns_nonce_valid = false\nhash = SHA-256(nonce || expected_state)
REE->TEE: ecall: SS_SERVER_AUTH_VERIFY_CMD(hash, sig, &valid)
note over TEE: import pubkey from M-mode constants\npsa_verify_hash()\ndestroy ephemeral key
TEE->REE: return valid = 1 or 0
note over REE: if !valid: send ERROR\nread actual GPIO level\ncompare expected vs actual
REE->Server: "MATCH" or "MISMATCH"
Server->REE: TCP close
```

### Packet format: CMD_CHECK_STATUS (0x01)

```
Byte offset   Length   Field
0             1        Command byte (0x01)
1             1        Expected LED state (0x01 = ON, 0x00 = OFF)
2             32       Nonce (must match s_pending_nonce)
34            64       ECDSA signature: R (32B) || S (32B)
```
Total: 98 bytes

### Signed message

```
message  = nonce (32 bytes) || expected_state (1 byte)
hash     = SHA-256(message)              [computed in REE]
signature = ECDSA-P256-SHA256(hash, server_private_key)  [computed on server]
```

### Replay prevention

Each `CMD_GET_CHALLENGE` generates a fresh random nonce via `esp_fill_random()`. The nonce is stored in `s_pending_nonce` and flagged valid. On `CMD_CHECK_STATUS`, the flag is cleared immediately before the TEE call regardless of outcome — a replayed packet with the same nonce will fail the `memcmp` check.

---

## 5. What the TEE Guarantees (and What It Does Not)

### Guarantees

- **Public key integrity**: The server's public key lives in M-mode `.rodata`. REE code cannot overwrite it. An attacker with full control of the REE application cannot substitute their own public key to accept their own signatures.
- **Verification runs in M-mode**: The actual `psa_verify_hash()` call happens inside the TEE binary (which includes its own mbedTLS/PSA, compiled into `esp_tee.bin`). The PSA library called from within the service is the TEE's own copy, not the REE's.
- **M-mode assertion**: The service checks `esp_cpu_get_curr_privilege_level()` at entry and aborts if not in secure mode.

### Limitations (honest assessment)

- **Nonce state is in REE memory**: `s_pending_nonce` and `s_nonce_valid` live in U-mode RAM. A fully compromised REE could in theory restore a consumed nonce.
- **Hash is computed in REE**: The SHA-256 over `nonce || expected_state` is computed in `app_main.c` before the TEE call. A fully compromised REE controls what hash is passed in. The attack is still bounded: the adversary cannot forge a valid signature without the server's private key, so passing an arbitrary hash to the TEE service gains nothing.
- **`out_valid` pointer is in REE stack**: The TEE writes the result to a pointer in U-mode memory. The REE reads it after the call returns. In practice this is safe for synchronous code, but it is architecturally a write into REE memory.

In summary: the TEE closes the specific attack of *key substitution* by a REE-level attacker. It does not provide full protocol isolation.

---

## 6. Alternative Algorithms and Approaches

### Alternative signature algorithms

All of the following are supported by PSA Crypto in the TEE (mbedTLS backend):

| Algorithm              | PSA constant                        | Notes                                            |
|-----------------------|-------------------------------------|--------------------------------------------------|
| ECDSA-P256 (current)  | `PSA_ALG_ECDSA(PSA_ALG_SHA_256)`    | 64-byte sig, 32-byte hash, 65-byte pubkey        |
| ECDSA-P384            | `PSA_ALG_ECDSA(PSA_ALG_SHA_384)`    | Higher security margin, larger key/sig           |
| Ed25519               | `PSA_ALG_PURE_EDDSA`                | Deterministic, no hash param, faster verify      |
| RSA-PSS-2048          | `PSA_ALG_RSA_PSS(PSA_ALG_SHA_256)`  | Much larger key (256B pubkey), widely supported  |
| HMAC-SHA256           | `PSA_ALG_HMAC(PSA_ALG_SHA_256)`     | Symmetric — requires shared secret, not a pubkey |

Ed25519 would be a good alternative: deterministic signatures (no random required at signing time), faster verification, smaller 32-byte public key. It is available in mbedTLS 3.x which ships with IDF 6.x.

### Alternative trust anchoring approaches

| Approach                           | Public key location     | Compromise if REE taken |
|------------------------------------|------------------------|--------------------------|
| **Current (this project)**         | M-mode `.rodata`       | Key cannot be replaced   |
| Public key in REE flash            | REE `.rodata`          | Attacker can patch flash |
| Public key in NVS                  | REE NVS partition      | Attacker can write NVS   |
| Public key in TEE Secure Storage   | TEE encrypted NVS      | Provisioned at manufacture, updatable with auth |

The TEE Secure Storage approach (`tee_sec_storage` component) would allow key rotation without reflashing firmware, but requires a secure provisioning step at manufacture.

### Alternative transport security

The current protocol uses raw TCP with application-layer signatures. There is no channel encryption — the nonce, expected state, and signature are all visible in plaintext on the wire. Alternatives:

| Option       | What it adds                              | Complexity |
|--------------|-------------------------------------------|------------|
| Current      | Authentication only (signatures)          | Low        |
| TLS (mbedTLS)| Channel encryption + server cert auth     | Medium     |
| DTLS         | Same but UDP                              | Medium     |
| Noise Protocol | Lightweight mutual auth + encryption    | Medium     |

For a device that only reports LED state and verifies commands from a local server, plaintext with signatures is a reasonable tradeoff. Add TLS if the commands are sensitive or the network is untrusted.

---

## 7. Key Rotation

To rotate the server key:

1. Generate a new ECDSA-P256 keypair:
   ```python
   from cryptography.hazmat.primitives.asymmetric import ec
   from cryptography.hazmat.primitives import serialization
   k = ec.generate_private_key(ec.SECP256R1())
   pub = k.public_key().public_numbers()
   print('X:', pub.x.to_bytes(32,'big').hex())
   print('Y:', pub.y.to_bytes(32,'big').hex())
   print(k.private_bytes(serialization.Encoding.PEM,
         serialization.PrivateFormat.PKCS8,
         serialization.NoEncryption()).decode())
   ```

2. Update `SERVER_PUBKEY_X` and `SERVER_PUBKEY_Y` in `components/server_auth_service/server_auth_service.c`

3. Replace `SERVER_PRIVATE_KEY_PEM` in `server/server.py`

4. Rebuild and reflash — both binaries update (TEE binary with new pubkey, app binary unchanged)

---

## 8. File Map

```
tee_server_auth/
├── CMakeLists.txt                          Top-level build; registers TEE service via tee_project.cmake
├── sdkconfig.defaults                      TEE enabled, WiFi credentials, blink period
├── main/
│   ├── app_main.c                          REE application: WiFi, TCP server, LED blink, protocol handler
│   ├── Kconfig.projbuild                   menuconfig entries: WiFi, port, GPIO, blink period
│   └── CMakeLists.txt                      REE component deps
├── components/server_auth_service/
│   ├── server_auth_service.c               TEE-side service (M-mode only): pubkey + psa_verify_hash
│   ├── include/server_auth_service.h       Shared header (types, constants)
│   ├── sec_srv_tbl_server_auth.yml         Service table: id=200, args=3
│   ├── tee_project.cmake                   Registers component into TEE subproject build
│   └── CMakeLists.txt                      Conditional build (TEE vs REE)
└── server/
    └── server.py                           Python test client: get nonce, sign, send check
```
