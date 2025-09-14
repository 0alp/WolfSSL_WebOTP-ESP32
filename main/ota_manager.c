#include "ota_manager.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include <string.h>

static const char *TAG = "OTA_MANAGER";

// Global variables
static ota_config_t g_ota_config;
static TaskHandle_t g_ota_task_handle = NULL;
static ota_status_callback_t g_status_callback = NULL;
static bool g_ota_active = false;
static bool g_ota_initialized = false;

#define MAX_HTTP_OUTPUT_BUFFER 2048
#define OTA_BUFFER_SIZE 1024

// HTTP response handler for version check
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
    ESP_LOGI(TAG, "Current version: %s", current_version);
    
    // Store configuration
    strncpy(g_ota_config.server_host, server_host, sizeof(g_ota_config.server_host) - 1);
    g_ota_config.server_port = server_port;
    g_ota_config.use_https = use_https;
    strncpy(g_ota_config.current_version, current_version, sizeof(g_ota_config.current_version) - 1);
    g_ota_config.check_interval_minutes = 5; 
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
    
    // Configure HTTPS
    if (g_ota_config.use_https) {
        config.transport_type = HTTP_TRANSPORT_OVER_SSL;
        config.skip_cert_common_name_check = true;
        config.use_global_ca_store = false;
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
            char *update_available_str = strstr(local_response_buffer, "\"update_available\":");
            if (update_available_str && strstr(update_available_str, "true")) {
                char *latest_version_str = strstr(local_response_buffer, "\"latest_version\":");
                if (latest_version_str && latest_version) {
                    sscanf(latest_version_str, "\"latest_version\":\"%[^\"]\"", latest_version);
                }
                
                char *firmware_id_str = strstr(local_response_buffer, "\"id\":");
                if (firmware_id_str && firmware_id) {
                    sscanf(firmware_id_str, "\"id\":%d", firmware_id);
                }
                
                ESP_LOGI(TAG, "Update available! Version: %s, ID: %d", 
                         latest_version ? latest_version : "Unknown", 
                         firmware_id ? *firmware_id : 0);
                update_available = true;
                
                if (g_status_callback) {
                    g_status_callback("Update found", 0);
                }
            } else {
                ESP_LOGI(TAG, "Current version is latest: %s", g_ota_config.current_version);
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
    
    if (g_ota_config.use_https) {
        snprintf(url, sizeof(url), "https://%s:%d/api/firmware/download/%d", 
                 g_ota_config.server_host, g_ota_config.server_port, firmware_id);
    } else {
        snprintf(url, sizeof(url), "http://%s:%d/api/firmware/download/%d", 
                 g_ota_config.server_host, g_ota_config.server_port, firmware_id);
    }
    
    ESP_LOGI(TAG, "Downloading firmware: %s", url);
    
    if (g_status_callback) {
        g_status_callback("Downloading firmware...", 0);
    }
    
    esp_http_client_config_t config = {
        .url = url,
        .timeout_ms = 30000,
        .keep_alive_enable = true,
    };
    
    // Configure HTTPS
    if (g_ota_config.use_https) {
        config.transport_type = HTTP_TRANSPORT_OVER_SSL;
        config.skip_cert_common_name_check = true;
        config.use_global_ca_store = false;
    }
    
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client");
        return ESP_FAIL;
    }
    
    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return err;
    }
    
    int content_length = esp_http_client_fetch_headers(client);
    if (content_length < 0) {
        ESP_LOGE(TAG, "HTTP client fetch headers failed");
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "Firmware size: %d bytes", content_length);
    
    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (update_partition == NULL) {
        ESP_LOGE(TAG, "Failed to find OTA partition");
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "Writing to partition subtype %d at offset 0x%x",
             update_partition->subtype, update_partition->address);
    
    esp_ota_handle_t update_handle = 0;
    err = esp_ota_begin(update_partition, OTA_WITH_SEQUENTIAL_WRITES, &update_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed: %s", esp_err_to_name(err));
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return err;
    }
    
    ESP_LOGI(TAG, "esp_ota_begin succeeded");
    
    int binary_file_length = 0;
    char *upgrade_data_buf = malloc(OTA_BUFFER_SIZE);
    if (upgrade_data_buf == NULL) {
        ESP_LOGE(TAG, "Couldn't allocate memory to upgrade data buffer");
        esp_ota_abort(update_handle);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ESP_ERR_NO_MEM;
    }
    
    esp_app_desc_t new_app_info;
    bool image_header_was_checked = false;
    
    while (1) {
        int data_read = esp_http_client_read(client, upgrade_data_buf, OTA_BUFFER_SIZE);
        if (data_read < 0) {
            ESP_LOGE(TAG, "Error: SSL data read error");
            break;
        } else if (data_read > 0) {
            if (image_header_was_checked == false) {
                esp_app_desc_t *app_desc = (esp_app_desc_t *)upgrade_data_buf;
                ESP_LOGI(TAG, "New firmware version: %s", app_desc->version);
                
                if (sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t) > data_read) {
                    ESP_LOGE(TAG, "Received package is not fit len");
                    break;
                }
                
                memcpy(&new_app_info, &upgrade_data_buf[sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t)], sizeof(esp_app_desc_t));
                ESP_LOGI(TAG, "New firmware version: %s", new_app_info.version);
                
                err = validate_image_header(&new_app_info);
                if (err != ESP_OK) {
                    ESP_LOGE(TAG, "Image header validation failed");
                    break;
                }
                
                image_header_was_checked = true;
            }
            
            err = esp_ota_write(update_handle, (const void *)upgrade_data_buf, data_read);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "esp_ota_write failed: %s", esp_err_to_name(err));
                break;
            }
            
            binary_file_length += data_read;
            ESP_LOGD(TAG, "Written image length %d", binary_file_length);
            
            if (content_length > 0) {
                int progress_percent = (binary_file_length * 100) / content_length;
                if (g_status_callback) {
                    g_status_callback("Downloading...", progress_percent);
                }
            }
        } else if (data_read == 0) {
            ESP_LOGI(TAG, "Connection closed");
            break;
        }
    }
    
    ESP_LOGI(TAG, "Total Write binary data length: %d", binary_file_length);
    
    if (content_length != binary_file_length) {
        ESP_LOGE(TAG, "Download incomplete: expected %d bytes, got %d bytes", content_length, binary_file_length);
        esp_ota_abort(update_handle);
        free(upgrade_data_buf);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }
    
    err = esp_ota_end(update_handle);
    if (err != ESP_OK) {
        if (err == ESP_ERR_OTA_VALIDATE_FAILED) {
            ESP_LOGE(TAG, "Image validation failed, image is corrupted");
        } else {
            ESP_LOGE(TAG, "esp_ota_end failed (%s)!", esp_err_to_name(err));
        }
        free(upgrade_data_buf);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return err;
    }
    
    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)!", esp_err_to_name(err));
        free(upgrade_data_buf);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return err;
    }
    
    ESP_LOGI(TAG, "Firmware update successful");
    
    if (g_status_callback) {
        g_status_callback("Update successful, restarting...", 100);
    }
    
    free(upgrade_data_buf);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    
    if (g_ota_config.auto_restart) {
        ESP_LOGI(TAG, "System restarting...");
        vTaskDelay(1000 / portTICK_PERIOD_MS);
        esp_restart();
    }
    
    return ESP_OK;
}

static void ota_check_task(void *pvParameter)
{
    ESP_LOGI(TAG, "OTA control task started");
    g_ota_active = true;
    
    while (g_ota_active) {
        ESP_LOGI(TAG, "Checking for firmware update...");
        
        char latest_version[32] = {0};
        int firmware_id = 0;
        
        if (ota_manager_check_update(latest_version, &firmware_id)) {
            ESP_LOGI(TAG, "New firmware found! Version: %s", latest_version);
            
            esp_err_t ret = ota_manager_update_firmware(firmware_id);
            if (ret == ESP_OK) {
                ESP_LOGI(TAG, "Firmware update successful, updated to version %s", latest_version);
            } else {
                ESP_LOGE(TAG, "Firmware update failed: %s", esp_err_to_name(ret));
            }
        }
        
        vTaskDelay(pdMS_TO_TICKS(g_ota_config.check_interval_minutes * 60 * 1000));
    }
    
    ESP_LOGI(TAG, "OTA control task terminating...");
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
    
    ESP_LOGI(TAG, "Starting OTA control task (interval: %d minutes)...", 
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
        ESP_LOGE(TAG, "Failed to create OTA task");
        return ESP_FAIL;
    }
    
    return ESP_OK;
}

void ota_manager_stop_check(void)
{
    if (g_ota_task_handle != NULL) {
        ESP_LOGI(TAG, "Stopping OTA control task...");
        g_ota_active = false;
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void ota_manager_set_status_callback(ota_status_callback_t callback)
{
    g_status_callback = callback;
    ESP_LOGI(TAG, "OTA status callback set");
}

void ota_manager_set_check_interval(int minutes)
{
    if (minutes < 1) minutes = 1;
    g_ota_config.check_interval_minutes = minutes;
    ESP_LOGI(TAG, "OTA check interval: %d minutes", minutes);
}

void ota_manager_set_auto_restart(bool auto_restart)
{
    g_ota_config.auto_restart = auto_restart;
    ESP_LOGI(TAG, "Auto restart: %s", auto_restart ? "ENABLED" : "DISABLED");
}

bool ota_manager_is_active(void)
{
    return g_ota_active && (g_ota_task_handle != NULL);
}

const char* ota_manager_get_current_version(void)
{
    return g_ota_config.current_version;
}

void ota_manager_deinit(void)
{
    if (g_ota_initialized) {
        ota_manager_stop_check();
        g_ota_initialized = false;
        ESP_LOGI(TAG, "OTA Manager deinitialized");
    }
}