#ifndef WIFI_MANAGER_H
#define WIFI_MANAGER_H

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"

// WiFi event bits  
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

// WiFi configuration structure 
typedef struct {
    char ssid[32];
    char password[64];
    int max_retry;
    int retry_delay_ms;
} wifi_config_manager_t;

// WiFi status callback type    
typedef void (*wifi_status_callback_t)(bool connected, const char* ip_address);

/**
 * Start the WiFi manager   
 * @param ssid: WiFi SSID
 * @param password: WiFi password   
 * @param max_retry: Maximum retry attempts 
 * @return ESP_OK successful, ESP_FAIL failed
 */
esp_err_t wifi_manager_init(const char* ssid, const char* password, int max_retry);

/**
 * Initialize and start the WiFi connection 
 * @return ESP_OK successful
 */
esp_err_t wifi_manager_start(void);

/**
 * Wait for WiFi connection with timeout    
 * @param timeout_ms: Timeout in milliseconds (0 for indefinite)    
 * @return ESP_OK successful, ESP_FAIL failed, ESP_ERR_TIMEOUT timeout  
 */
esp_err_t wifi_manager_wait_connection(uint32_t timeout_ms);

/**
 * Control if WiFi is connected 
 * @return true if connected, false if not connected    
 */
bool wifi_manager_is_connected(void);

/**
 * Get the current IP address as a string
 * @param ip_str: Buffer to store the IP address (must be at least 16 bytes)    
 * @return ESP_OK successful, ESP_FAIL failed   
 */
esp_err_t wifi_manager_get_ip(char* ip_str);

/**
 * Get the current RSSI value (dBm) 
 * @return RSSI value in dBm, or -100 if not connected  
 */
int8_t wifi_manager_get_rssi(void);

/**
 * Stop the WiFi connection 
 */
void wifi_manager_stop(void);

/**
 * Restart the WiFi connection  
 * @return ESP_OK successful, ESP_FAIL failed   
 */
esp_err_t wifi_manager_restart(void);

/**
 * Set WiFi status callback
 * @param callback: The function to call on status changes
 */
void wifi_manager_set_status_callback(wifi_status_callback_t callback);

/**
 * Print current WiFi information to the logs
 */
void wifi_manager_print_info(void);

#endif // WIFI_MANAGER_H