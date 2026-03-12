idf_component_register(SRCS "app_main.c"
                       INCLUDE_DIRS "."
                       PRIV_REQUIRES esp_wifi esp_netif nvs_flash mbedtls
                                     esp_driver_gpio esp_event esp_tee
                                     server_auth_service)
