/**
  * THIS FILE WAS AUTOMATICALLY GENERATED. DO NOT EDIT!
  */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif
void _ss_invalid_secure_service(void);
void _ss_mmu_hal_map_region(void);
void _ss_mmu_hal_unmap_region(void);
void _ss_mmu_hal_vaddr_to_paddr(void);
void _ss_mmu_hal_paddr_to_vaddr(void);
void _ss_esp_rom_route_intr_matrix(void);
void _ss_rv_utils_intr_enable(void);
void _ss_rv_utils_intr_disable(void);
void _ss_rv_utils_intr_set_priority(void);
void _ss_rv_utils_intr_set_type(void);
void _ss_rv_utils_intr_set_threshold(void);
void _ss_rv_utils_intr_edge_ack(void);
void _ss_rv_utils_intr_global_enable(void);
void _ss_wdt_hal_init(void);
void _ss_wdt_hal_deinit(void);
void _ss_esp_aes_intr_alloc(void);
void _ss_esp_aes_crypt_cbc(void);
void _ss_esp_aes_crypt_cfb8(void);
void _ss_esp_aes_crypt_cfb128(void);
void _ss_esp_aes_crypt_ctr(void);
void _ss_esp_aes_crypt_ecb(void);
void _ss_esp_aes_crypt_ofb(void);
void _ss_esp_sha(void);
void _ss_esp_sha_block(void);
void _ss_esp_sha_dma(void);
void _ss_esp_sha_read_digest_state(void);
void _ss_esp_sha_write_digest_state(void);
void _ss_esp_crypto_sha_enable_periph_clk(void);
void _ss_esp_hmac_calculate(void);
void _ss_esp_hmac_jtag_enable(void);
void _ss_esp_hmac_jtag_disable(void);
void _ss_esp_ds_sign(void);
void _ss_esp_ds_start_sign(void);
void _ss_esp_ds_is_busy(void);
void _ss_esp_ds_finish_sign(void);
void _ss_esp_ds_encrypt_params(void);
void _ss_esp_crypto_mpi_enable_periph_clk(void);
void _ss_esp_ecc_point_multiply(void);
void _ss_esp_ecc_point_verify(void);
void _ss_esp_sha_set_mode(void);
void _ss_esp_tee_sec_storage_clear_key(void);
void _ss_esp_tee_sec_storage_gen_key(void);
void _ss_esp_tee_sec_storage_ecdsa_sign(void);
void _ss_esp_tee_sec_storage_ecdsa_get_pubkey(void);
void _ss_esp_tee_sec_storage_aead_encrypt(void);
void _ss_esp_tee_sec_storage_aead_decrypt(void);
void _ss_esp_tee_sec_storage_ecdsa_sign_pbkdf2(void);
void _ss_esp_tee_ota_begin(void);
void _ss_esp_tee_ota_write(void);
void _ss_esp_tee_ota_end(void);
void _ss_server_auth_verify_cmd(void);
#ifdef __cplusplus
}
#endif
