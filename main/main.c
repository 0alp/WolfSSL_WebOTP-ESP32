#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_wpa2.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_netif.h"
#include "esp_tls.h"
#include "nvs_flash.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_ota_ops.h"
#include "lwip/err.h"
#include "lwip/sys.h"

// WolfSSL headers
#include "sdkconfig.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

static const char *TAG = "ESP32_OTA_CLIENT";

// WiFi settings - Change these!
#define WIFI_SSID        "NETDISCOVER"
#define WIFI_PASSWORD    "1233211231"

// Server settings - Change these!  
#define SERVER_HOST      "46.101.115.117"  // or domain
#define SERVER_PORT      8000                // 80 for HTTP, 443 for HTTPS or other port    
#define USE_HTTPS        0                  // 1=HTTPS, 0=HTTP

// Firmware Info
#define CURRENT_VERSION  "1.0.0"
#define MAX_HTTP_OUTPUT_BUFFER 2048

// WiFi event group
static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static int s_retry_num = 0;
#define MAX_RETRY 5

// WiFi event handler
static void event_handler(void* arg, esp_event_base_t event_base,
                         int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < MAX_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "Retrying WiFi connection %d/%d", s_retry_num, MAX_RETRY);
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        ESP_LOGI(TAG,"WiFi connection failed");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "IP received:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

void wifi_init_sta(void)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASSWORD,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {
                .capable = true,
                .required = false
            },
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_start() );

    ESP_LOGI(TAG, "WiFi started. SSID:%s", WIFI_SSID);

    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
                                         WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                         pdFALSE,
                                         pdFALSE,
                                         portMAX_DELAY);

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "WiFi connection successful");
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGI(TAG, "WiFi connection failed");
    } else {
        ESP_LOGE(TAG, "Unexpected event on WiFi connection");
    }
}

// HTTP response handler
esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    static int output_len;       
    
    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            if (!esp_http_client_is_chunked_response(evt->client)) {
                if (evt->user_data) {
                    memcpy(evt->user_data + output_len, evt->data, evt->data_len);
                }
            }
            output_len += evt->data_len;
            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
            output_len = 0;
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
            int mbedtls_err = 0;
            esp_err_t err = esp_tls_get_and_clear_last_error(evt->data, &mbedtls_err, NULL);
            if (err != 0) {
                ESP_LOGI(TAG, "Last esp error code: 0x%x", err);
                ESP_LOGI(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
            }
            output_len = 0;
            break;
        case HTTP_EVENT_REDIRECT:
            ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
            break;
        default:
            break;
    }
    return ESP_OK;
}

bool check_firmware_update(char* latest_version, int* firmware_id, char* download_url)
{
    char url[256];
    char local_response_buffer[MAX_HTTP_OUTPUT_BUFFER] = {0};
    
    // Generate URL 
    if (USE_HTTPS) {
        snprintf(url, sizeof(url), "https://%s:%d/api/firmware/check/%s", SERVER_HOST, SERVER_PORT, CURRENT_VERSION);
    } else {
        snprintf(url, sizeof(url), "http://%s:%d/api/firmware/check/%s", SERVER_HOST, SERVER_PORT, CURRENT_VERSION);
    }
    
    ESP_LOGI(TAG, "Checking for update: %s", url);
    
    esp_http_client_config_t config = {
        .url = url,
        .event_handler = _http_event_handler,
        .user_data = local_response_buffer,        
        .disable_auto_redirect = true,
    };
    
    if (USE_HTTPS) {
        config.transport_type = HTTP_TRANSPORT_OVER_SSL;
        config.skip_cert_common_name_check = true;  // Self-signed certficate
    }
    
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);
    
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTPS Status = %d, content_length = %lld",
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
        ESP_LOGI(TAG, "Response: %s", local_response_buffer);
        
        // JSON parsing 
        char *update_available_str = strstr(local_response_buffer, "\"update_available\":");
        if (update_available_str) {
            if (strstr(update_available_str, "true")) {
                // Get Latest Version   
                char *latest_version_str = strstr(local_response_buffer, "\"latest_version\":");
                if (latest_version_str) {
                    sscanf(latest_version_str, "\"latest_version\":\"%[^\"]\"", latest_version);
                }
                
                // Get Firmware ID
                char *firmware_id_str = strstr(local_response_buffer, "\"id\":");
                if (firmware_id_str) {
                    sscanf(firmware_id_str, "\"id\":%d", firmware_id);
                }
                
                ESP_LOGI(TAG, "Update available! Version: %s, ID: %d", latest_version, *firmware_id);
                esp_http_client_cleanup(client);
                return true;
            }
        }
        
        ESP_LOGI(TAG, "Current version used: %s", CURRENT_VERSION);
    } else {
        ESP_LOGE(TAG, "Update check failed: %s", esp_err_to_name(err));
    }
    
    esp_http_client_cleanup(client);
    return false;
}

esp_err_t validate_image_header(esp_app_desc_t *new_app_info)
{
    if (new_app_info == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    const esp_app_desc_t *running_app_info = esp_app_get_description();
    ESP_LOGI(TAG, "Running firmware version: %s", running_app_info->version);
    ESP_LOGI(TAG, "New firmware version: %s", new_app_info->version);

    return ESP_OK;
}

esp_err_t download_and_update_firmware(int firmware_id)
{
    char url[256];
    
    // Download URL 
    if (USE_HTTPS) {
        snprintf(url, sizeof(url), "https://%s:%d/api/firmware/download/%d", SERVER_HOST, SERVER_PORT, firmware_id);
    } else {
        snprintf(url, sizeof(url), "http://%s:%d/api/firmware/download/%d", SERVER_HOST, SERVER_PORT, firmware_id);
    }
    ESP_LOGI(TAG, "Firmware is downloading: %s", url);
    
    esp_http_client_config_t config = {
        .url = url,
        .timeout_ms = 30000,
        .keep_alive_enable = true,
    };
    
    if (USE_HTTPS) {
        config.transport_type = HTTP_TRANSPORT_OVER_SSL;
        config.skip_cert_common_name_check = true;  // Self-signed certficate 
    }
    
    esp_https_ota_config_t ota_config = {
        .http_config = &config,
        .http_client_init_cb = NULL, 
        .partial_http_download = true,
        .max_http_request_size = 1024,
    };

    esp_https_ota_handle_t https_ota_handle = NULL;
    esp_err_t err = esp_https_ota_begin(&ota_config, &https_ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ESP HTTPS OTA Begin failed");
        return err;
    }

    esp_app_desc_t app_desc;
    err = esp_https_ota_get_img_desc(https_ota_handle, &app_desc);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_https_ota_read_img_desc failed");
        goto ota_end;
    }
    err = validate_image_header(&app_desc);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "image header verification failed");
        goto ota_end;
    }

    int binary_file_length = 0;
    while (1) {
        err = esp_https_ota_perform(https_ota_handle);
        if (err != ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
            break;
        }
        binary_file_length += 1024;
        ESP_LOGD(TAG, "Downloaded data: %d bytes", binary_file_length);
    }

    if (esp_https_ota_is_complete_data_received(https_ota_handle) != true) {
        ESP_LOGE(TAG, "Complete data could not be retrieved.");
    } else {
        ESP_LOGI(TAG, "Firmware download completed. Total bytes: %d", binary_file_length);
        err = esp_https_ota_finish(https_ota_handle);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "ESP HTTPS OTA update successful. Restarting...");
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            esp_restart();
        } else {
            if (err == ESP_ERR_OTA_VALIDATE_FAILED) {
                ESP_LOGE(TAG, "Image verification failed, image is corrupt");
            } else {
                ESP_LOGE(TAG, "ESP HTTPS OTA finish failed: (%s)!", esp_err_to_name(err));
            }
        }
    }

ota_end:
    esp_https_ota_abort(https_ota_handle);
    return err;
}

void ota_task(void *pvParameter)
{
    ESP_LOGI(TAG, "OTA Update Task has started");
    
    while (1) {
        ESP_LOGI(TAG, "Checking for update...");
        
        char latest_version[32] = {0};
        int firmware_id = 0;
        char download_url[256] = {0};
        
        if (check_firmware_update(latest_version, &firmware_id, download_url)) {
            ESP_LOGI(TAG, "New firmware found! Version:%s", latest_version);
            ESP_LOGI(TAG, "Downloading and updating firmware...");
            
            esp_err_t ret = download_and_update_firmware(firmware_id);
            if (ret == ESP_OK) {
                ESP_LOGI(TAG, "Firmware update successful!");
            } else {
                ESP_LOGE(TAG, "Firmware update failed: %s", esp_err_to_name(ret));
            }
        }
        
        vTaskDelay(60000 / portTICK_PERIOD_MS);
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "Starting ESP32 WolfSSL OTA Client...");
    ESP_LOGI(TAG, "Current firmware version: %s", CURRENT_VERSION);
    ESP_LOGI(TAG, "Server: %s:%d (%s)", SERVER_HOST, SERVER_PORT, USE_HTTPS ? "HTTPS" : "HTTP");
    
    // Start NVS 
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    ESP_LOGI(TAG, "Starting WolfSSL...");
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        ESP_LOGE(TAG, "WolfSSL_Init failed: %d", ret);
        return;
    }
    ESP_LOGI(TAG, "WolfSSL launched. Versiyon: %s", wolfSSL_lib_version());
    
    wifi_init_sta();
    
    xTaskCreate(&ota_task, "ota_task", 8192, NULL, 5, NULL);
    
    while (1) {
        ESP_LOGI(TAG, "The system is running... Free heap: %d bytes", esp_get_free_heap_size());
        vTaskDelay(30000 / portTICK_PERIOD_MS);
    }
}