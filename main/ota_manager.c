#include "ota_manager.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "OTA_MANAGER";

// Global variables
static ota_config_t g_ota_config;
static TaskHandle_t g_ota_task_handle = NULL;
static ota_status_callback_t g_status_callback = NULL;
static bool g_ota_active = false;
static bool g_ota_initialized = false;

#define MAX_HTTP_OUTPUT_BUFFER 2048

// HTTP response handler
static esp_err_t ota_http_event_handler(esp_http_client_event_t *evt)
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

// Image header validation
static esp_err_t validate_image_header(esp_app_desc_t *new_app_info)
{
    if (new_app_info == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    const esp_app_desc_t *running_app_info = esp_app_get_description();
    ESP_LOGI(TAG, "Running firmware: %s", running_app_info->version);
    ESP_LOGI(TAG, "New firmware: %s", new_app_info->version);

    return ESP_OK;
}

esp_err_t ota_manager_init(const char* server_host, int server_port, 
                          bool use_https, const char* current_version)
{
    if (g_ota_initialized) {
        ESP_LOGW(TAG, "OTA Manager already initialized");
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "OTA Manager being started ...");
    ESP_LOGI(TAG, "Server: %s:%d (%s)", server_host, server_port, use_https ? "HTTPS" : "HTTP");
    ESP_LOGI(TAG, "Currrent version: %s", current_version);
    
    // Register configuration
    strncpy(g_ota_config.server_host, server_host, sizeof(g_ota_config.server_host) - 1);
    g_ota_config.server_port = server_port;
    g_ota_config.use_https = use_https;
    strncpy(g_ota_config.current_version, current_version, sizeof(g_ota_config.current_version) - 1);
    g_ota_config.check_interval_minutes = 1; 
    g_ota_config.auto_restart = true;
    
    g_ota_initialized = true;
    ESP_LOGI(TAG, "OTA Manager has been initialized successfully");
    
    return ESP_OK;
}

bool ota_manager_check_update(char* latest_version, int* firmware_id)
{
    if (!g_ota_initialized) {
        ESP_LOGE(TAG, "OTA Manager not initialized");
        return false;
    }
    
    char url[256];
    char local_response_buffer[MAX_HTTP_OUTPUT_BUFFER] = {0};
    
    // Create the check URL
    if (g_ota_config.use_https) {
        snprintf(url, sizeof(url), "https://%s:%d/api/firmware/check/%s", 
                 g_ota_config.server_host, g_ota_config.server_port, g_ota_config.current_version);
    } else {
        snprintf(url, sizeof(url), "http://%s:%d/api/firmware/check/%s", 
                 g_ota_config.server_host, g_ota_config.server_port, g_ota_config.current_version);
    }
    
    ESP_LOGI(TAG, "Checking for update: %s", url);
    
    esp_http_client_config_t config = {
        .url = url,
        .event_handler = ota_http_event_handler,
        .user_data = local_response_buffer,        
        .disable_auto_redirect = true,
        .timeout_ms = 10000,
    };
    
    if (g_ota_config.use_https) {
        config.transport_type = HTTP_TRANSPORT_OVER_SSL;
        config.skip_cert_common_name_check = true;
    }
    
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);
    
    bool update_available = false;
    
    if (err == ESP_OK) {
        int status_code = esp_http_client_get_status_code(client);
        ESP_LOGI(TAG, "HTTP Status = %d, content_length = %lld",
                status_code, esp_http_client_get_content_length(client));
        ESP_LOGI(TAG, "Response: %s", local_response_buffer);
        
        if (status_code == 200) {
            // JSON parsing
            char *update_available_str = strstr(local_response_buffer, "\"update_available\":");
            if (update_available_str && strstr(update_available_str, "true")) {
                // Get latest version string 
                char *latest_version_str = strstr(local_response_buffer, "\"latest_version\":");
                if (latest_version_str && latest_version) {
                    sscanf(latest_version_str, "\"latest_version\":\"%[^\"]\"", latest_version);
                }
                
                // Get Firmware ID 
                char *firmware_id_str = strstr(local_response_buffer, "\"id\":");
                if (firmware_id_str && firmware_id) {
                    sscanf(firmware_id_str, "\"id\":%d", firmware_id);
                }
                
                ESP_LOGI(TAG, "Update available! Version: %s, ID: %d", 
                         latest_version ? latest_version : "Unknown", 
                         firmware_id ? *firmware_id : 0);
                update_available = true;
                
                if (g_status_callback) {
                    g_status_callback("Update has been found", 0);
                }
            } else {
                ESP_LOGI(TAG, "Current version is used: %s", g_ota_config.current_version);
            }
        }
    } else {
        ESP_LOGE(TAG, "Update check failed: %s", esp_err_to_name(err));
        if (g_status_callback) {
            g_status_callback("Update check failed", -1);
        }
    }
    
    esp_http_client_cleanup(client);
    return update_available;
}

esp_err_t ota_manager_update_firmware(int firmware_id)
{
    if (!g_ota_initialized) {
        ESP_LOGE(TAG, "OTA Manager not initialized");
        return ESP_FAIL;
    }
    
    char url[256];
    
    // Create Download URL 
    if (g_ota_config.use_https) {
        snprintf(url, sizeof(url), "https://%s:%d/api/firmware/download/%d", 
                 g_ota_config.server_host, g_ota_config.server_port, firmware_id);
    } else {
        snprintf(url, sizeof(url), "http://%s:%d/api/firmware/download/%d", 
                 g_ota_config.server_host, g_ota_config.server_port, firmware_id);
    }
    
    ESP_LOGI(TAG, "Firmware downloading: %s", url);
    
    if (g_status_callback) {
        g_status_callback("Firmware downloading...", 0);
    }
    
    esp_http_client_config_t config = {
        .url = url,
        .timeout_ms = 30000,
        .keep_alive_enable = true,
    };
    
    if (g_ota_config.use_https) {
        config.transport_type = HTTP_TRANSPORT_OVER_SSL;
        config.skip_cert_common_name_check = true; // The same issue with [NOTE1] 
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
        if (g_status_callback) {
            g_status_callback("OTA startup error", -1);
        }
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
        ESP_LOGE(TAG, "Image header validation failed");
        goto ota_end;
    }

    int binary_file_length = 0;
    int progress_percent = 0;
    
    while (1) {
        err = esp_https_ota_perform(https_ota_handle);
        if (err != ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
            break;
        }
        binary_file_length += 1024;
        
        // Progress callback
        int new_progress = (binary_file_length * 100) / 1024000; // Assuming max size 1MB for demo
        if (new_progress != progress_percent && new_progress <= 100) {
            progress_percent = new_progress;
            if (g_status_callback) {
                g_status_callback("Downloading...", progress_percent);
            }
        }
        
        ESP_LOGD(TAG, "Downloaded data: %d bytes", binary_file_length);
    }

    if (esp_https_ota_is_complete_data_received(https_ota_handle) != true) {
        ESP_LOGE(TAG, "Complete data was not received.");
        if (g_status_callback) {
            g_status_callback("Download error", -1);
        }
    } else {
        ESP_LOGI(TAG, "Firmware download has been completed.. Total: %d bytes", binary_file_length);
        
        if (g_status_callback) {
            g_status_callback("Firmware is being implemented...", 100);
        }
        
        err = esp_https_ota_finish(https_ota_handle);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "ESP HTTPS OTA finish successful");
            
            if (g_status_callback) {
                g_status_callback("Uploading successful, restarting...", 100);
            }
            
            if (g_ota_config.auto_restart) {
                ESP_LOGI(TAG, "System is being restarted...");
                vTaskDelay(1000 / portTICK_PERIOD_MS);
                esp_restart();
            }
        } else {
            if (err == ESP_ERR_OTA_VALIDATE_FAILED) {
                ESP_LOGE(TAG, "ESP HTTPS OTA finish failed: Image validation failed");
            } else {
                ESP_LOGE(TAG, "ESP HTTPS OTA finish failed: (%s)!", esp_err_to_name(err));
            }
            if (g_status_callback) {
                g_status_callback("Uploading error", -1);
            }
        }
    }

ota_end:
    esp_https_ota_abort(https_ota_handle);
    return err;
}

// OTA Control Task
static void ota_check_task(void *pvParameter)
{
    ESP_LOGI(TAG, "OTA control task has been started");
    g_ota_active = true;
    
    while (g_ota_active) {
        ESP_LOGI(TAG, "Checking for firmware update...");
        
        char latest_version[32] = {0};
        int firmware_id = 0;
        
        if (ota_manager_check_update(latest_version, &firmware_id)) {
            ESP_LOGI(TAG, "New firmware has been found! Version: %s", latest_version);
            
            esp_err_t ret = ota_manager_update_firmware(firmware_id);
            if (ret == ESP_OK) {
                ESP_LOGI(TAG, "Firmware update successful, updated to version %s", latest_version);
            } else {
                ESP_LOGE(TAG, "Firmware update failed: %s", esp_err_to_name(ret));
            }
        }
        
        vTaskDelay(pdMS_TO_TICKS(g_ota_config.check_interval_minutes * 60 * 1000));
    }
    
    ESP_LOGI(TAG, "OTA control task being terminated...");
    g_ota_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t ota_manager_start_check(void)
{
    if (!g_ota_initialized) {
        ESP_LOGE(TAG, "OTA Manager not initialized");
        return ESP_FAIL;
    }
    
    if (g_ota_task_handle != NULL) {
        ESP_LOGW(TAG, "OTA control task already running");
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "OTA control task is being started (interval: %d minutes)...", 
             g_ota_config.check_interval_minutes);
    
    BaseType_t ret = xTaskCreate(
        ota_check_task,
        "ota_check",
        8192,
        NULL,
        5,
        &g_ota_task_handle
    );
    
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "OTA task could not be created");
        return ESP_FAIL;
    }
    
    return ESP_OK;
}

void ota_manager_stop_check(void)
{
    if (g_ota_task_handle != NULL) {
        ESP_LOGI(TAG, "OTA control task is being stopped...");
        g_ota_active = false;
        
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void ota_manager_set_status_callback(ota_status_callback_t callback)
{
    g_status_callback = callback;
    ESP_LOGI(TAG, "OTA status callback has been set");
}

void ota_manager_set_check_interval(int minutes)
{
    if (minutes < 1) minutes = 1;
    g_ota_config.check_interval_minutes = minutes;
    ESP_LOGI(TAG, "OTA control interval: %d minutes", minutes);
}

void ota_manager_set_auto_restart(bool auto_restart)
{
    g_ota_config.auto_restart = auto_restart;
    ESP_LOGI(TAG, "Automatic restart: %s", auto_restart ? "OPEN" : "CLOSED");
}

bool ota_manager_is_active(void)
{
    return g_ota_active && (g_ota_task_handle != NULL);
}

const char* ota_manager_get_current_version(void)
{
    return g_ota_config.current_version;
}