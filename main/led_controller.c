#include "led_controller.h"
#include <string.h>

static const char *TAG = "LED_CONTROLLER";

// Global LED configuration
static led_config_t g_led_config;
static TaskHandle_t g_blink_task_handle = NULL;

// LED blink task
static void led_blink_task(void *pvParameter)
{
    led_config_t *config = (led_config_t *)pvParameter;
    
    ESP_LOGI(TAG, "LED blink task started - Pin %d, Period: %d ms", 
             config->pin, config->blink_period_ms);
    
    bool led_state = false;
    
    while (config->is_active) {
        gpio_set_level(config->pin, led_state);
        
        if (led_state) {
            ESP_LOGD(TAG, "LED Pin %d ON", config->pin);
        } else {
            ESP_LOGD(TAG, "LED Pin %d OFF", config->pin);
        }
        
        led_state = !led_state;
        vTaskDelay(pdMS_TO_TICKS(config->blink_period_ms));
    }
    
    ESP_LOGI(TAG, "LED blink task is stopped - Pin %d", config->pin);
    vTaskDelete(NULL);
}

esp_err_t led_controller_init(gpio_num_t pin)
{
    ESP_LOGI(TAG, "LED Controller initializing - Pin %d", pin);
    
    // GPIO confuguration
    gpio_config_t io_conf = {
        .intr_type = GPIO_INTR_DISABLE,
        .mode = GPIO_MODE_OUTPUT,
        .pin_bit_mask = (1ULL << pin),
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .pull_up_en = GPIO_PULLUP_DISABLE,
    };
    
    esp_err_t ret = gpio_config(&io_conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "GPIO configuration failed: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Global config initialization 
    g_led_config.pin = pin;
    g_led_config.mode = LED_MODE_OFF;
    g_led_config.blink_period_ms = 1000;
    g_led_config.is_active = false;
    
    // Ensure LED is off initially  
    gpio_set_level(pin, 0);
    
    ESP_LOGI(TAG, "LED Controller initialized successfully - Pin %d", pin);
    return ESP_OK;
}

void led_turn_on(gpio_num_t pin)
{
    gpio_set_level(pin, 1);
    ESP_LOGI(TAG, "LED Pin %d turned ON", pin);
}

void led_turn_off(gpio_num_t pin)
{
    gpio_set_level(pin, 0);
    ESP_LOGI(TAG, "LED Pin %d turned OFF", pin);
}

void led_toggle(gpio_num_t pin)
{
    int current_level = gpio_get_level(pin);
    gpio_set_level(pin, !current_level);
    ESP_LOGD(TAG, "LED Pin %d TOGGLE - New state: %s", 
             pin, !current_level ? "ON" : "OFF");
}

bool led_get_state(gpio_num_t pin)
{
    return gpio_get_level(pin);
}

esp_err_t led_start_blink(gpio_num_t pin, uint32_t period_ms)
{
    // Stop any existing blink task 
    led_stop_blink(pin);
    
    ESP_LOGI(TAG, "LED blink starting - Pin %d, Period: %d ms", pin, period_ms);
    
    g_led_config.pin = pin;
    g_led_config.mode = LED_MODE_BLINK_SLOW;
    g_led_config.blink_period_ms = period_ms;
    g_led_config.is_active = true;
    
    // Create the blink task
    BaseType_t ret = xTaskCreate(
        led_blink_task,
        "led_blink",
        2048,
        &g_led_config,
        3,
        &g_blink_task_handle
    );
    
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "LED blink task could not be created");
        g_led_config.is_active = false;
        return ESP_FAIL;
    }
    
    return ESP_OK;
}

void led_stop_blink(gpio_num_t pin)
{
    if (g_blink_task_handle != NULL) {
        ESP_LOGI(TAG, "LED blink is stopped - Pin %d", pin);
        
        g_led_config.is_active = false;
        
        // Wait for the task to terminate
        vTaskDelay(pdMS_TO_TICKS(100));
        
        g_blink_task_handle = NULL;
        
      
        led_turn_off(pin);
    }
}

esp_err_t led_init_for_version(const char* version)
{
    gpio_num_t led_pin;
    
    if (strcmp(version, "1.0.0") == 0) {
        led_pin = LED_PIN_V1;
        ESP_LOGI(TAG, "Firmware v%s - LED Pin %d will be used", version, LED_PIN_V1);
    } else if (strcmp(version, "1.1.0") == 0) {
        led_pin = LED_PIN_V2;
        ESP_LOGI(TAG, "Firmware v%s - LED Pin %d will be used", version, LED_PIN_V2);
    } else {
        ESP_LOGW(TAG, "Unknown firmware version: %s, default Pin %d will be used", 
                 version, LED_PIN_V1);
        led_pin = LED_PIN_V1;
    }
    
    // start the LED controller 
    esp_err_t ret = led_controller_init(led_pin);
    if (ret != ESP_OK) {
        return ret;
    }
    
    led_turn_on(led_pin);
    vTaskDelay(pdMS_TO_TICKS(1000)); 
    
    ret = led_start_blink(led_pin, 2000); 
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "LED blink initialization failed");
        return ret;
    }
    
    ESP_LOGI(TAG, "LED initialized successfully  - Pin %d, Version: %s", led_pin, version);
    return ESP_OK;
}

void led_run_test(void)
{
    ESP_LOGI(TAG, "LED test starting...");
    
    gpio_num_t test_pins[] = {LED_PIN_V1, LED_PIN_V2};
    int num_pins = sizeof(test_pins) / sizeof(test_pins[0]);
    
    for (int i = 0; i < num_pins; i++) {
        ESP_LOGI(TAG, "Pin %d being tested...", test_pins[i]);
        
       
        led_controller_init(test_pins[i]);
        
       
        for (int j = 0; j < 3; j++) {
            led_turn_on(test_pins[i]);
            vTaskDelay(pdMS_TO_TICKS(500));
            led_turn_off(test_pins[i]);
            vTaskDelay(pdMS_TO_TICKS(500));
        }
        
        
        led_start_blink(test_pins[i], 200);
        vTaskDelay(pdMS_TO_TICKS(2000));
        led_stop_blink(test_pins[i]);
        
        ESP_LOGI(TAG, "Pin %d test completed", test_pins[i]);
    }
    
    ESP_LOGI(TAG, "LED test completed");
}