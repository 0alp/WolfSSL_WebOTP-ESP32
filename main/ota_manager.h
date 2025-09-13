#ifndef OTA_MANAGER_H
#define OTA_MANAGER_H

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_err.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_ota_ops.h"

// OTA configuration structure  
typedef struct {
    char server_host[128];
    int server_port;
    bool use_https;
    char current_version[32];
    int check_interval_minutes;
    bool auto_restart;
} ota_config_t;

// OTA status callback type 
typedef void (*ota_status_callback_t)(const char* status, int progress);

/**
 * start the OTA manager    
 * @param server_host: Server host or IP address
 * @param server_port: Server's port number 
 * @param use_https: Use HTTPS if true, HTTP if false
 * @param current_version: Current firmware version string  
 * @return ESP_OK successful, ESP_FAIL failed   
 */
esp_err_t ota_manager_init(const char* server_host, int server_port, 
                          bool use_https, const char* current_version);

/**
 * start the OTA check task 
 * @return ESP_OK successful, ESP_FAIL failed 
 */
esp_err_t ota_manager_start_check(void);

/**
 * stop the OTA check task  
 */
void ota_manager_stop_check(void);

/**
 * check for firmware update
 * @param latest_version: Latest version string (output)    
 * @param firmware_id: Firmware ID (output)
 * @return true if update available, false if no update available or error  
 */
bool ota_manager_check_update(char* latest_version, int* firmware_id);

/**
 * Download and apply firmware update   
 * @param firmware_id: Firmware ID to download  
 * @return ESP_OK successful, ESP_FAIL failed 
 */
esp_err_t ota_manager_update_firmware(int firmware_id);

/**
 * Save OTA status callback 
 * @param callback: The function to call with status updates    
 */
void ota_manager_set_status_callback(ota_status_callback_t callback);

/**
 * Set the OTA check interval   
 * @param minutes: Interval in minutes (minimum 1 minute)   
 */
void ota_manager_set_check_interval(int minutes);

/**
 * Set automatic restart after successful update    
 * @param auto_restart: true to enable, false to disable    
 */
void ota_manager_set_auto_restart(bool auto_restart);

/**
 * Check if OTA manager is active   
 * @return true if active, false if not active  
 */
bool ota_manager_is_active(void);

/**
 * Get the current firmware version string  
 * @return Current version string   
 */
const char* ota_manager_get_current_version(void);

#endif // OTA_MANAGER_H