#include "wifi_manager.h"
#include "lwip/err.h"
#include "lwip/sys.h"

static const char *TAG = "WIFI_MANAGER";

// Global variables
static wifi_config_manager_t g_wifi_config;
static EventGroupHandle_t g_wifi_event_group;
static wifi_status_callback_t g_status_callback = NULL;
static int g_retry_num = 0;
static bool g_wifi_initialized = false;
static char g_ip_address[16] = {0};

// WiFi event handler
static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                              int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        ESP_LOGI(TAG, "WiFi connection stage started and trying to connect...");
        esp_wifi_connect();
    } 
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (g_retry_num < g_wifi_config.max_retry) {
            esp_wifi_connect();
            g_retry_num++;
            ESP_LOGI(TAG, "Retrying WiFi connection %d/%d", 
                     g_retry_num, g_wifi_config.max_retry);
        } else {
            xEventGroupSetBits(g_wifi_event_group, WIFI_FAIL_BIT);
            ESP_LOGE(TAG, "WiFi connection failed after %d attempts", g_wifi_config.max_retry);
        }
        
        // Callback 
        if (g_status_callback) {
            g_status_callback(false, "");
        }
    } 
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        snprintf(g_ip_address, sizeof(g_ip_address), IPSTR, IP2STR(&event->ip_info.ip));
        
        ESP_LOGI(TAG, "WiFi connection successful! IP: %s", g_ip_address);
        g_retry_num = 0;
        xEventGroupSetBits(g_wifi_event_group, WIFI_CONNECTED_BIT);
        
        // Callback 
        if (g_status_callback) {
            g_status_callback(true, g_ip_address);
        }
    }
}

esp_err_t wifi_manager_init(const char* ssid, const char* password, int max_retry)
{
    if (g_wifi_initialized) {
        ESP_LOGW(TAG, "WiFi Manager already initialized");
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "WiFi Manager being started ...");
    ESP_LOGI(TAG, "SSID: %s", ssid);
    ESP_LOGI(TAG, "Max retry: %d", max_retry);
    
    // Store configuration
    strncpy(g_wifi_config.ssid, ssid, sizeof(g_wifi_config.ssid) - 1);
    strncpy(g_wifi_config.password, password, sizeof(g_wifi_config.password) - 1);
    g_wifi_config.max_retry = max_retry;
    g_wifi_config.retry_delay_ms = 2000;
    
    // Create event group   
    g_wifi_event_group = xEventGroupCreate();
    if (g_wifi_event_group == NULL) {
        ESP_LOGE(TAG, "Event group could not be created");
        return ESP_FAIL;
    }
    
    // Initialize TCP/IP stack and default WiFi station 
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    
    // Initialize WiFi with default configuration
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    
    // Register event handlers  
    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT,
        ESP_EVENT_ANY_ID,
        &wifi_event_handler,
        NULL,
        &instance_any_id));
        
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT,
        IP_EVENT_STA_GOT_IP,
        &wifi_event_handler,
        NULL,
        &instance_got_ip));
    
    g_wifi_initialized = true;
    ESP_LOGI(TAG, "WiFi Manager has been initialized successfully");
    
    return ESP_OK;
}

esp_err_t wifi_manager_start(void)
{
    if (!g_wifi_initialized) {
        ESP_LOGE(TAG, "WiFi Manager did not initialized");
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "WiFi connection being started...");
    
    wifi_config_t wifi_config = {
        .sta = {
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {
                .capable = true,
                .required = false
            },
        },
    };
    
    // Set SSID and password    
    strncpy((char*)wifi_config.sta.ssid, g_wifi_config.ssid, sizeof(wifi_config.sta.ssid));
    strncpy((char*)wifi_config.sta.password, g_wifi_config.password, sizeof(wifi_config.sta.password));
    
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    
    ESP_LOGI(TAG, "WiFi was started, SSID: %s", g_wifi_config.ssid);
    
    return ESP_OK;
}

esp_err_t wifi_manager_wait_connection(uint32_t timeout_ms)
{
    if (!g_wifi_initialized) {
        ESP_LOGE(TAG, "WiFi manager did not initialized");
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "WiFi connection being waiting (timeout: %d ms)", timeout_ms);
    
    TickType_t timeout_ticks = (timeout_ms == 0) ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
    
    EventBits_t bits = xEventGroupWaitBits(
        g_wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE,
        pdFALSE,
        timeout_ticks
    );
    
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "WiFi connection established");
        return ESP_OK;
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGE(TAG, "WiFi connection failed");
        return ESP_FAIL;
    } else {
        ESP_LOGW(TAG, "WiFi connection timeout");
        return ESP_ERR_TIMEOUT;
    }
}

bool wifi_manager_is_connected(void)
{
    if (!g_wifi_initialized) {
        return false;
    }
    
    EventBits_t bits = xEventGroupGetBits(g_wifi_event_group);
    return (bits & WIFI_CONNECTED_BIT) != 0;
}

esp_err_t wifi_manager_get_ip(char* ip_str)
{
    if (!wifi_manager_is_connected() || ip_str == NULL) {
        return ESP_FAIL;
    }
    
    strcpy(ip_str, g_ip_address);
    return ESP_OK;
}

int8_t wifi_manager_get_rssi(void)
{
    if (!wifi_manager_is_connected()) {
        return -100; // low RSSI value indicating no connection
    }
    
    wifi_ap_record_t ap_info;
    esp_err_t ret = esp_wifi_sta_get_ap_info(&ap_info);
    if (ret == ESP_OK) {
        return ap_info.rssi;
    }
    
    return -100;
}

void wifi_manager_stop(void)
{
    if (!g_wifi_initialized) {
        return;
    }
    
    ESP_LOGI(TAG, "WiFi being stopped...");
    
    esp_wifi_stop();
    xEventGroupClearBits(g_wifi_event_group, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);
    
    memset(g_ip_address, 0, sizeof(g_ip_address));
    
    // Callback 
    if (g_status_callback) {
        g_status_callback(false, "");
    }
    
    ESP_LOGI(TAG, "WiFi has been stopped");
}

esp_err_t wifi_manager_restart(void)
{
    ESP_LOGI(TAG, "WiFi being restarted...");
    
    wifi_manager_stop();
    vTaskDelay(pdMS_TO_TICKS(1000)); 
    
    g_retry_num = 0;
    return wifi_manager_start();
}

void wifi_manager_set_status_callback(wifi_status_callback_t callback)
{
    g_status_callback = callback;
    ESP_LOGI(TAG, "WiFi state callback has been set");
}

void wifi_manager_print_info(void)
{
    if (!wifi_manager_is_connected()) {
        ESP_LOGI(TAG, "WiFi status: Connection not established");
        return;
    }
    
    ESP_LOGI(TAG, "=== WiFi Info ===");
    ESP_LOGI(TAG, "SSID: %s", g_wifi_config.ssid);
    ESP_LOGI(TAG, "IP Addr: %s", g_ip_address);
    ESP_LOGI(TAG, "RSSI: %d dBm", wifi_manager_get_rssi());
    ESP_LOGI(TAG, "State: Established");
    ESP_LOGI(TAG, "====================");
}