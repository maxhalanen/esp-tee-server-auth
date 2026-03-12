/*
 * Server Authentication Service — TEE-side Implementation
 *
 * THIS FILE RUNS IN M-MODE (TEE) ONLY.
 *
 * Verifies that an incoming command was signed by the legitimate server using
 * ECDSA-P256-SHA256. The server's public key is a compile-time constant here
 * in M-mode — the REE cannot read it, modify it, or substitute a different key.
 *
 * To rotate the server key: update SERVER_PUBKEY_X / SERVER_PUBKEY_Y below
 * and reflash the TEE firmware.
 *
 * Generating a new server keypair:
 *   python3 -c "
 *     from cryptography.hazmat.primitives.asymmetric import ec
 *     from cryptography.hazmat.primitives import serialization
 *     k = ec.generate_private_key(ec.SECP256R1())
 *     pub = k.public_key().public_numbers()
 *     print('X:', pub.x.to_bytes(32,'big').hex())
 *     print('Y:', pub.y.to_bytes(32,'big').hex())
 *     print(k.private_bytes(serialization.Encoding.PEM,
 *           serialization.PrivateFormat.PKCS8,
 *           serialization.NoEncryption()).decode())
 *   "
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
 * Server ECDSA-P256 public key — hardcoded at build time.
 * Replace these bytes with your own server's public key coordinates.
 * The corresponding private key lives only on the server (server/server.py).
 */
static const uint8_t SERVER_PUBKEY_X[SERVER_AUTH_KEY_LEN] = {
    0x1C, 0x62, 0x0D, 0x81, 0x4B, 0x6A, 0x3F, 0x23,
    0xDA, 0xB7, 0x19, 0x81, 0xF2, 0xAA, 0x54, 0x85,
    0xF7, 0xFF, 0x90, 0x54, 0x53, 0xC5, 0xD5, 0xAC,
    0x3A, 0xAC, 0xF8, 0x96, 0x27, 0x2F, 0x7F, 0x04
};

static const uint8_t SERVER_PUBKEY_Y[SERVER_AUTH_KEY_LEN] = {
    0x67, 0xF4, 0x54, 0xC6, 0x3D, 0xC8, 0x30, 0x5A,
    0x9B, 0x60, 0x90, 0x90, 0x1F, 0xE9, 0xD0, 0x55,
    0xA3, 0x84, 0xBC, 0x21, 0x01, 0x24, 0xE7, 0xF0,
    0x3D, 0x85, 0xE9, 0x56, 0x05, 0xF8, 0x31, 0x4B
};

esp_err_t _ss_server_auth_verify_cmd(const uint8_t *hash,
                                     const server_auth_sig_t *signature,
                                     int *out_valid)
{
    if (esp_cpu_get_curr_privilege_level() != ESP_CPU_S_MODE) {
        ESP_LOGE(TAG, "Not running in secure mode!");
        return ESP_ERR_INVALID_STATE;
    }

    if (hash == NULL || signature == NULL || out_valid == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    *out_valid = 0;

    ESP_LOGI(TAG, "Secure service call: server signature verify in M-mode");

    /* Build uncompressed point entirely from M-mode constants — REE has no input here */
    uint8_t pub_buf[1 + SERVER_AUTH_KEY_LEN * 2];
    pub_buf[0] = 0x04;
    memcpy(pub_buf + 1,                    SERVER_PUBKEY_X, SERVER_AUTH_KEY_LEN);
    memcpy(pub_buf + 1 + SERVER_AUTH_KEY_LEN, SERVER_PUBKEY_Y, SERVER_AUTH_KEY_LEN);

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    psa_key_id_t key_id = 0;
    psa_status_t status = psa_import_key(&attr, pub_buf, sizeof(pub_buf), &key_id);
    psa_reset_key_attributes(&attr);

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to import server pubkey: %d", (int)status);
        return ESP_FAIL;
    }

    status = psa_verify_hash(key_id,
                             PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                             hash, SERVER_AUTH_HASH_LEN,
                             signature->rs, SERVER_AUTH_SIG_LEN);
    psa_destroy_key(key_id);

    if (status == PSA_SUCCESS) {
        ESP_LOGI(TAG, "Server signature VALID");
        *out_valid = 1;
    } else {
        ESP_LOGW(TAG, "Server signature INVALID (psa: %d)", (int)status);
        *out_valid = 0;
    }

    return ESP_OK;
}
