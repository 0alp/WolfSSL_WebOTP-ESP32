#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"

// WolfSSL configuration
#define WOLFSSL_ESPRESSIF
#define WOLFSSL_ESP32  
#define NO_WRITEV
#define HAVE_ECC

// WolfSSL headers
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

// Project headers
#include "wifi_manager.h"
#include "led_controller.h"
#include "ota_manager.h"

static const char *TAG = "MAIN";

// Application configuration    
#define APP_VERSION         "1.0.0"
#define WIFI_SSID          "NETDISCOVER"
#define WIFI_PASSWORD      "1233211231"
#define WIFI_MAX_RETRY     5

#define SERVER_HOST        "46.101.115.117"
#define SERVER_PORT        8000
#define USE_HTTPS         0

// The function to handle WiFi status changes
static void on_wifi_status_changed(bool connected, const char* ip_address)
{
    if (connected) {
        ESP_LOGI(TAG, "WiFi connection has been established  %s", ip_address);
        
        // When WiFi is connected, start OTA checks 
        ota_manager_start_check();
    } else {
        ESP_LOGW(TAG, "WiFi connection has been lost");
        
        // When WiFi is disconnected, stop OTA checks   
        ota_manager_stop_check();
    }
}

// The function to initialize the system components
static esp_err_t system_init(void)
{
    ESP_LOGI(TAG, "The system is being initialized...");
    
    // Start NVS flash  
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    // Start WolfSSL
    ESP_LOGI(TAG, "WolfSSL is being initialized...");
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        ESP_LOGE(TAG, "WolfSSL_Init failed: %d", ret);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "WolfSSL has been initialized. Version: %s", wolfSSL_lib_version());
    
    return ESP_OK;
}

// The task to monitor system status    
static void system_monitor_task(void *pvParameter)
{
    char ip_str[16];
    
    while (1) {
        ESP_LOGI(TAG, "=== System State ===");
        ESP_LOGI(TAG, "Firmware Version: %s", APP_VERSION);
        ESP_LOGI(TAG, "Free Heap: %d bytes", esp_get_free_heap_size());
        
        if (wifi_manager_is_connected()) {
            wifi_manager_get_ip(ip_str);
            ESP_LOGI(TAG, "WiFi: Connected (%s)", ip_str);
            ESP_LOGI(TAG, "RSSI: %d dBm", wifi_manager_get_rssi());
        } else {
            ESP_LOGI(TAG, "WiFi: Disconnected");
        }
        
        ESP_LOGI(TAG, "==================");
        
        vTaskDelay(pdMS_TO_TICKS(30000)); 
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "ESP32 OTA Client being started...");
    ESP_LOGI(TAG, "Firmware Version: %s", APP_VERSION);
    ESP_LOGI(TAG, "Server: %s:%d (%s)", SERVER_HOST, SERVER_PORT, USE_HTTPS ? "HTTPS" : "HTTP");
    
    // Start the system 
    if (system_init() != ESP_OK) {
        ESP_LOGE(TAG, "System initialization failed");
        return;
    }
    
    // Start the LED based on firmware version  
    esp_err_t ret = led_init_for_version(APP_VERSION);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "LED initialization failed");
        return;
    }
    
    // Initialize WiFi manager
    ret = wifi_manager_init(WIFI_SSID, WIFI_PASSWORD, WIFI_MAX_RETRY);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "WiFi Manager initialization failed");
        return;
    }
    
    // Register WiFi status callback    
    wifi_manager_set_status_callback(on_wifi_status_changed);
    
    // Initialize OTA manager   
    ret = ota_manager_init(SERVER_HOST, SERVER_PORT, USE_HTTPS, APP_VERSION);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "OTA Manager initialization failed");
        return;
    }
    
    // Initialize and start the WiFi connection 
    ret = wifi_manager_start();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "WiFi initialization failed");
        return;
    }
    
    // wait for WiFi connection with timeout    
    ret = wifi_manager_wait_connection(10000); 
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "WiFi connection could not be established but continuing...");
    }
    
    // Initialize and start the system monitor task 
    xTaskCreate(&system_monitor_task, "system_monitor", 3072, NULL, 2, NULL);
    
    ESP_LOGI(TAG, "System initialization is complete.");
    
    // The main task can be deleted or can perform other duties here
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}