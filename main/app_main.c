/*
 * ESP TEE Server Authentication Demo — Symmetric HMAC-SHA256
 *
 * The device runs a TCP server. The server authenticates itself by sending an
 * HMAC-SHA256 MAC computed with the shared secret key. The device verifies
 * the MAC inside the TEE (shared key never exposed to REE), then compares the
 * server's expected LED state against the actual GPIO level.
 *
 * The device also MACs its response, enabling the server to verify the reply
 * came from a genuine device — mutual authentication.
 *
 * Protocol (one connection per exchange):
 *   CMD_GET_CHALLENGE (0x00) — device responds with 32-byte random nonce
 *   CMD_CHECK_STATUS  (0x01) — server sends:
 *                              [0x01][1B expected_state][32B nonce][32B MAC]
 *                              MAC = HMAC-SHA256(nonce || expected_state, key)
 *                              device responds: [1B result][32B MAC]
 *                              result: 0x01 = MATCH, 0x00 = MISMATCH
 *                              MAC = HMAC-SHA256(nonce || result, key)
 *
 * The nonce is single-use: accepted once then invalidated to prevent replay.
 *
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#include <string.h>
#include <stdatomic.h>
#include <sys/param.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

#include "esp_tee.h"
#include "secure_service_num.h"
#include "server_auth_service.h"
#include "sdkconfig.h"

/* -------------------------------------------------------------------------- */
/*  Configuration                                                              */
/* -------------------------------------------------------------------------- */
#define LED_GPIO        CONFIG_EXAMPLE_LED_GPIO
#define TCP_PORT        CONFIG_EXAMPLE_TCP_PORT
#define WIFI_SSID       CONFIG_EXAMPLE_WIFI_SSID
#define WIFI_PASS       CONFIG_EXAMPLE_WIFI_PASSWORD
#define WIFI_MAX_RETRY  CONFIG_EXAMPLE_WIFI_MAXIMUM_RETRY

#define CMD_GET_CHALLENGE  0x00
#define CMD_CHECK_STATUS   0x01

#define NONCE_LEN       SERVER_AUTH_NONCE_LEN
#define BLINK_PERIOD_MS CONFIG_EXAMPLE_BLINK_PERIOD_MS

static const char *TAG = "tee_server_auth";

/* -------------------------------------------------------------------------- */
/*  Pending nonce — one outstanding challenge at a time                        */
/* -------------------------------------------------------------------------- */
static uint8_t  s_pending_nonce[NONCE_LEN];
static bool     s_nonce_valid = false;

/* -------------------------------------------------------------------------- */
/*  LED state                                                                  */
/* -------------------------------------------------------------------------- */
static atomic_int s_led_state = 0;

/* -------------------------------------------------------------------------- */
/*  WiFi                                                                       */
/* -------------------------------------------------------------------------- */
static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
static int s_retry_num = 0;

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < WIFI_MAX_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "Retrying WiFi (%d/%d)", s_retry_num, WIFI_MAX_RETRY);
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta(void)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler, NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler, NULL, &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
                                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdFALSE, pdFALSE, portMAX_DELAY);
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Connected to WiFi");
    } else {
        ESP_LOGE(TAG, "Failed to connect to WiFi");
    }
}

/* -------------------------------------------------------------------------- */
/*  LED blink task                                                             */
/* -------------------------------------------------------------------------- */
static void led_blink_task(void *pvParameters)
{
    while (1) {
        int state = atomic_load(&s_led_state);
        state = !state;
        atomic_store(&s_led_state, state);
        gpio_set_level(LED_GPIO, state);
        ESP_LOGI(TAG, "LED toggled -> %s", state ? "ON" : "OFF");
        vTaskDelay(pdMS_TO_TICKS(BLINK_PERIOD_MS));
    }
}

/* -------------------------------------------------------------------------- */
/*  Handle a single TCP client connection                                      */
/* -------------------------------------------------------------------------- */
static void handle_client(int sock)
{
    /* Largest packet: CMD_CHECK_STATUS = [cmd][expected][nonce][MAC] */
    uint8_t rx_buf[1 + 1 + NONCE_LEN + SERVER_AUTH_MAC_LEN];

    int len = recv(sock, rx_buf, sizeof(rx_buf), 0);
    if (len <= 0) {
        ESP_LOGW(TAG, "No data from client");
        return;
    }

    uint8_t cmd = rx_buf[0];

    if (cmd == CMD_GET_CHALLENGE) {
        /* Generate a fresh nonce and send it — invalidate any previous one */
        esp_fill_random(s_pending_nonce, NONCE_LEN);
        s_nonce_valid = true;
        send(sock, s_pending_nonce, NONCE_LEN, 0);
        ESP_LOGI(TAG, "Issued challenge nonce");
        return;
    }

    if (cmd == CMD_CHECK_STATUS) {
        /* Packet: [0x01][1B expected_state][32B nonce][32B MAC] */
        if (len < 1 + 1 + NONCE_LEN + SERVER_AUTH_MAC_LEN) {
            ESP_LOGW(TAG, "CHECK_STATUS packet too short (%d bytes)", len);
            send(sock, "ERROR: too short\n", 17, 0);
            return;
        }

        if (!s_nonce_valid) {
            ESP_LOGW(TAG, "No pending challenge — request one first");
            send(sock, "ERROR: no challenge\n", 20, 0);
            return;
        }

        uint8_t expected_state   = rx_buf[1];
        const uint8_t *rx_nonce  = &rx_buf[2];

        if (memcmp(rx_nonce, s_pending_nonce, NONCE_LEN) != 0) {
            ESP_LOGW(TAG, "Nonce mismatch — possible replay");
            s_nonce_valid = false;
            send(sock, "ERROR: nonce mismatch\n", 22, 0);
            return;
        }

        /* Consume nonce immediately */
        s_nonce_valid = false;

        /* Build verify message: nonce || expected_state */
        uint8_t verify_msg[SERVER_AUTH_MSG_LEN];
        memcpy(verify_msg, s_pending_nonce, NONCE_LEN);
        verify_msg[NONCE_LEN] = expected_state;

        server_auth_mac_t mac;
        memcpy(mac.bytes, &rx_buf[2 + NONCE_LEN], SERVER_AUTH_MAC_LEN);

        /* Verify server MAC inside the TEE — shared key never leaves M-mode */
        int valid = 0;
        uint32_t ret = esp_tee_service_call_with_noniram_intr_disabled(
            4, SS_SERVER_AUTH_VERIFY_MAC, verify_msg, &mac, &valid);

        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "TEE verify service call failed: 0x%lx", (unsigned long)ret);
            send(sock, "ERROR: tee fault\n", 17, 0);
            return;
        }

        if (!valid) {
            ESP_LOGW(TAG, "CHECK_STATUS REJECTED — invalid server MAC");
            send(sock, "ERROR: auth failed\n", 19, 0);
            return;
        }

        /* MAC valid — compare expected vs actual LED state */
        int actual = atomic_load(&s_led_state);
        ESP_LOGI(TAG, "Server expects LED: %s | Actual LED: %s",
                 expected_state ? "ON" : "OFF",
                 actual         ? "ON" : "OFF");

        uint8_t result_byte = ((expected_state != 0) == (actual != 0)) ? 0x01 : 0x00;

        /* Compute response MAC inside the TEE — proves response is from this device */
        uint8_t resp_msg[SERVER_AUTH_MSG_LEN];
        memcpy(resp_msg, s_pending_nonce, NONCE_LEN);
        resp_msg[NONCE_LEN] = result_byte;

        server_auth_mac_t resp_mac;
        uint32_t ret2 = esp_tee_service_call_with_noniram_intr_disabled(
            3, SS_SERVER_AUTH_COMPUTE_MAC, resp_msg, &resp_mac);

        if (ret2 != ESP_OK) {
            ESP_LOGE(TAG, "TEE compute service call failed: 0x%lx", (unsigned long)ret2);
            send(sock, "ERROR: tee fault\n", 17, 0);
            return;
        }

        /* Send [result_byte][32B MAC] */
        uint8_t response[1 + SERVER_AUTH_MAC_LEN];
        response[0] = result_byte;
        memcpy(response + 1, resp_mac.bytes, SERVER_AUTH_MAC_LEN);
        send(sock, response, sizeof(response), 0);

        ESP_LOGI(TAG, result_byte ? "STATUS MATCH" : "STATUS MISMATCH");
        return;
    }

    ESP_LOGW(TAG, "Unknown command: 0x%02x", cmd);
    send(sock, "ERROR: unknown cmd\n", 19, 0);
}

/* -------------------------------------------------------------------------- */
/*  TCP server task                                                            */
/* -------------------------------------------------------------------------- */
static void tcp_server_task(void *pvParameters)
{
    char addr_str[INET_ADDRSTRLEN];

    struct sockaddr_in dest_addr = {
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_family      = AF_INET,
        .sin_port        = htons(TCP_PORT),
    };

    int listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (listen_sock < 0) {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(listen_sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    listen(listen_sock, 1);

    ESP_LOGI(TAG, "TCP server listening on port %d", TCP_PORT);

    while (1) {
        struct sockaddr_in source_addr;
        socklen_t addr_len = sizeof(source_addr);
        int sock = accept(listen_sock, (struct sockaddr *)&source_addr, &addr_len);
        if (sock < 0) {
            ESP_LOGE(TAG, "Accept failed: errno %d", errno);
            break;
        }

        inet_ntoa_r(source_addr.sin_addr, addr_str, sizeof(addr_str));
        ESP_LOGI(TAG, "Connection from %s", addr_str);

        handle_client(sock);

        shutdown(sock, 0);
        close(sock);
    }

    close(listen_sock);
    vTaskDelete(NULL);
}

/* -------------------------------------------------------------------------- */
/*  app_main                                                                   */
/* -------------------------------------------------------------------------- */
void app_main(void)
{
    ESP_LOGI(TAG, "=== ESP TEE Server Authentication Demo (Symmetric HMAC) ===");

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* Set up LED GPIO */
    gpio_reset_pin(LED_GPIO);
    gpio_set_direction(LED_GPIO, GPIO_MODE_INPUT_OUTPUT);
    gpio_set_level(LED_GPIO, 0);

    wifi_init_sta();

    xTaskCreate(led_blink_task,  "led_blink",  2048, NULL, 5, NULL);
    xTaskCreate(tcp_server_task, "tcp_server", 4096, NULL, 5, NULL);
}
