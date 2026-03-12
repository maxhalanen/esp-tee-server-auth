/*
 * Server Authentication Service — Custom TEE Secure Service
 *
 * Shared header used by both the TEE-side implementation (M-mode) and the
 * REE application (U-mode).
 *
 * The shared HMAC-SHA256 key is hardcoded inside the TEE service
 * implementation. The REE only passes message buffers and MACs — it has no
 * ability to read or substitute the key.
 *
 * Two services:
 *   server_auth_verify_mac  — verify the server's MAC on an incoming command
 *   server_auth_compute_mac — compute the device's MAC on an outgoing response
 *
 * Both operate on a 33-byte message: nonce (32B) || data_byte (1B)
 *
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#pragma once

#include <stdint.h>
#include "esp_err.h"

#define SERVER_AUTH_NONCE_LEN  32  /* Random challenge nonce                */
#define SERVER_AUTH_MAC_LEN    32  /* HMAC-SHA256 output: 32 bytes          */
#define SERVER_AUTH_MSG_LEN    (SERVER_AUTH_NONCE_LEN + 1)  /* nonce || byte */

typedef struct {
    uint8_t bytes[SERVER_AUTH_MAC_LEN];
} server_auth_mac_t;

/**
 * @brief Verify a server-sent HMAC-SHA256 MAC inside the TEE.
 *
 * @param msg       33-byte message: nonce (32B) || expected_state (1B)
 * @param mac       32-byte HMAC-SHA256 received from server
 * @param out_valid Output: 1 if MAC valid, 0 otherwise
 * @return ESP_OK on success (inspect out_valid for result), error otherwise
 */
esp_err_t server_auth_verify_mac(const uint8_t *msg,
                                  const server_auth_mac_t *mac,
                                  int *out_valid);

/**
 * @brief Compute a device response HMAC-SHA256 inside the TEE.
 *
 * @param msg     33-byte message: nonce (32B) || result_byte (1B)
 * @param out_mac Output: 32-byte HMAC-SHA256 to send with response
 * @return ESP_OK on success, error otherwise
 */
esp_err_t server_auth_compute_mac(const uint8_t *msg,
                                   server_auth_mac_t *out_mac);
