#ifndef LED_CONTROLLER_H
#define LED_CONTROLLER_H

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "esp_log.h"

// Pin definitions  
#define LED_PIN_V1       18    // for version 1.0.0 
#define LED_PIN_V2       8     // for version 1.1.0 

// LED mods
typedef enum {
    LED_MODE_OFF = 0,
    LED_MODE_ON,
    LED_MODE_BLINK_SLOW,
    LED_MODE_BLINK_FAST,
    LED_MODE_BLINK_PATTERN
} led_mode_t;

// LED configuration structure  
typedef struct {
    gpio_num_t pin;
    led_mode_t mode;
    uint32_t blink_period_ms;
    bool is_active;
} led_config_t;

/**
 * start the LED controller 
 * @param pin: Led pin number   
 * @return ESP_OK successful, ESP_FAIL failed
 */
esp_err_t led_controller_init(gpio_num_t pin);

/**
 * Turn ON the LED
 * @param pin: Led pin number   
 */
void led_turn_on(gpio_num_t pin);

/**
 * Turn OFF the LED
 * @param pin: Led pin number   
 */
void led_turn_off(gpio_num_t pin);

/**
 * Toggle the current state of the LED  
 * @param pin: Led pin number   
 */
void led_toggle(gpio_num_t pin);

/**
 * Start the LED blink mode 
 * @param pin: Led pin number   
 * @param period_ms: Blink period (ms)
 */
esp_err_t led_start_blink(gpio_num_t pin, uint32_t period_ms);

/**
 * Stop the LED blink mode  
 * @param pin: Led pin number   
 */
void led_stop_blink(gpio_num_t pin);

/**
 * Get the current state of the LED
 * @param pin: Led pin number   
 * @return true: LED is ON, false: LED is OFF       
 */
bool led_get_state(gpio_num_t pin);

/**
 * Start the LED based on firmware version  
 * @param version: Firmware version (example: "1.0.0")
 * @return ESP_OK successed, ESP_FAIL failed
 */
esp_err_t led_init_for_version(const char* version);

/**
 * Led test function, tests all defined LED pins    
 */
void led_run_test(void);

#endif // LED_CONTROLLER_H