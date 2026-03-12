/*
 * Server Authentication Service — Custom TEE Secure Service
 *
 * Shared header used by both the TEE-side implementation (M-mode) and the
 * REE application (U-mode).
 *
 * The server's ECDSA-P256 public key is hardcoded inside the TEE service
 * implementation. The REE only passes the hash and signature — it has no
 * ability to substitute a different public key.
 *
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#pragma once

#include <stdint.h>
#include "esp_err.h"

#define SERVER_AUTH_KEY_LEN   32  /* P-256: 32 bytes per coordinate */
#define SERVER_AUTH_SIG_LEN   64  /* R (32 bytes) || S (32 bytes)   */
#define SERVER_AUTH_HASH_LEN  32  /* SHA-256 output                 */

typedef struct {
    uint8_t rs[SERVER_AUTH_SIG_LEN];  /* ECDSA signature: R || S */
} server_auth_sig_t;

/**
 * @brief Verify a server-signed command inside the TEE.
 *
 * The server's ECDSA-P256 public key is hardcoded in the TEE service and
 * never exposed to the REE. The REE passes only the pre-computed SHA-256
 * hash and the raw R||S signature received from the server.
 *
 * @param hash       SHA-256 digest of the signed message (32 bytes)
 * @param signature  Raw ECDSA-P256 signature: R || S (64 bytes)
 * @param out_valid  Output: 1 if signature is valid, 0 otherwise
 * @return ESP_OK on success (inspect out_valid for result), error otherwise
 */
esp_err_t server_auth_verify_cmd(const uint8_t *hash,
                                 const server_auth_sig_t *signature,
                                 int *out_valid);
