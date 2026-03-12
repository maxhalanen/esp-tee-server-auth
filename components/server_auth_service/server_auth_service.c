/*
 * Server Authentication Service — TEE-side Implementation
 *
 * THIS FILE RUNS IN M-MODE (TEE) ONLY.
 *
 * Provides two secure services using HMAC-SHA256 with a shared secret key:
 *
 *   server_auth_verify_mac  — authenticates incoming server commands
 *   server_auth_compute_mac — authenticates outgoing device responses
 *
 * Both sides holding the same key enables mutual authentication:
 *   - Device verifies server commands  (server proves it knows the key)
 *   - Server verifies device responses (device proves it knows the key)
 *
 * The key is a compile-time constant in M-mode .rodata. REE code cannot
 * read or modify it. It is protected from physical flash extraction only
 * when flash encryption is enabled on the device.
 *
 * To rotate the key:
 *   1. Generate 32 random bytes (e.g. python3 -c "import os; print(os.urandom(32).hex())")
 *   2. Update SHARED_KEY below
 *   3. Update SHARED_KEY_HEX in server/server.py
 *   4. Rebuild and reflash
 *
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#include <string.h>

#include "esp_cpu.h"
#include "esp_err.h"
#include "esp_log.h"
#include "psa/crypto.h"
#include "esp_tee.h"
#include "secure_service_num.h"
#include "server_auth_service.h"

static const char *TAG = "server_auth";

/*
 * Shared HMAC-SHA256 key — 32 bytes, hardcoded at build time in M-mode.
 * Must match SHARED_KEY_HEX in server/server.py.
 */
static const uint8_t SHARED_KEY[SERVER_AUTH_NONCE_LEN] = {
    0xA3, 0x7F, 0x2C, 0x8E, 0x51, 0xD4, 0x9B, 0x6A,
    0xF0, 0x3E, 0xC7, 0x82, 0x4D, 0x19, 0xB5, 0x2F,
    0x8C, 0x6E, 0x0A, 0x73, 0xD8, 0x45, 0xF1, 0x9C,
    0x2B, 0xE7, 0x54, 0x38, 0x0D, 0xC6, 0xA9, 0x1E
};

/* Import the shared key into PSA with the given usage flag. */
static psa_status_t import_hmac_key(psa_key_usage_t usage, psa_key_id_t *key_id)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_status_t st = psa_import_key(&attr, SHARED_KEY, sizeof(SHARED_KEY), key_id);
    psa_reset_key_attributes(&attr);
    return st;
}

/*
 * Verify the server's HMAC-SHA256 over msg (nonce || expected_state).
 * Called from REE via SS_SERVER_AUTH_VERIFY_MAC.
 */
esp_err_t _ss_server_auth_verify_mac(const uint8_t *msg,
                                      const server_auth_mac_t *mac,
                                      int *out_valid)
{
    if (esp_cpu_get_curr_privilege_level() != ESP_CPU_S_MODE) {
        ESP_LOGE(TAG, "Not running in secure mode!");
        return ESP_ERR_INVALID_STATE;
    }

    if (msg == NULL || mac == NULL || out_valid == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    *out_valid = 0;

    ESP_LOGI(TAG, "Secure service: verify server MAC in M-mode");

    psa_key_id_t key_id = 0;
    psa_status_t status = import_hmac_key(PSA_KEY_USAGE_VERIFY_MESSAGE, &key_id);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to import HMAC key: %d", (int)status);
        return ESP_FAIL;
    }

    status = psa_mac_verify(key_id,
                            PSA_ALG_HMAC(PSA_ALG_SHA_256),
                            msg, SERVER_AUTH_MSG_LEN,
                            mac->bytes, SERVER_AUTH_MAC_LEN);
    psa_destroy_key(key_id);

    if (status == PSA_SUCCESS) {
        ESP_LOGI(TAG, "Server MAC VALID");
        *out_valid = 1;
    } else {
        ESP_LOGW(TAG, "Server MAC INVALID (psa: %d)", (int)status);
        *out_valid = 0;
    }

    return ESP_OK;
}

/*
 * Compute the device's HMAC-SHA256 over msg (nonce || result_byte).
 * Called from REE via SS_SERVER_AUTH_COMPUTE_MAC.
 */
esp_err_t _ss_server_auth_compute_mac(const uint8_t *msg,
                                       server_auth_mac_t *out_mac)
{
    if (esp_cpu_get_curr_privilege_level() != ESP_CPU_S_MODE) {
        ESP_LOGE(TAG, "Not running in secure mode!");
        return ESP_ERR_INVALID_STATE;
    }

    if (msg == NULL || out_mac == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(TAG, "Secure service: compute response MAC in M-mode");

    psa_key_id_t key_id = 0;
    psa_status_t status = import_hmac_key(PSA_KEY_USAGE_SIGN_MESSAGE, &key_id);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to import HMAC key: %d", (int)status);
        return ESP_FAIL;
    }

    size_t mac_len = 0;
    status = psa_mac_compute(key_id,
                             PSA_ALG_HMAC(PSA_ALG_SHA_256),
                             msg, SERVER_AUTH_MSG_LEN,
                             out_mac->bytes, SERVER_AUTH_MAC_LEN,
                             &mac_len);
    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to compute MAC: %d", (int)status);
        return ESP_FAIL;
    }

    return ESP_OK;
}
