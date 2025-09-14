#ifndef FIRMWARE_SIGNATURE_H
#define FIRMWARE_SIGNATURE_H

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

// RSA key size (2048 bit)
#define RSA_KEY_SIZE_BITS 2048
#define RSA_KEY_SIZE_BYTES (RSA_KEY_SIZE_BITS / 8)
#define RSA_SIGNATURE_SIZE RSA_KEY_SIZE_BYTES

// SHA256 hash size
#define SHA256_HASH_SIZE 32

// Firmware signature structure
typedef struct {
    uint8_t signature[RSA_SIGNATURE_SIZE];
    uint8_t hash[SHA256_HASH_SIZE];
    uint32_t firmware_size;
    char version[32];
    uint32_t timestamp;
} firmware_signature_t;

/**
 * Initialize signature verification system
 * @param public_key_pem: PEM formatted public key
 * @return ESP_OK if successful, error code otherwise
 */
esp_err_t signature_init(const char* public_key_pem);

/**
 * Verify firmware signature
 * @param firmware_data: Firmware binary data
 * @param firmware_size: Size of firmware data
 * @param signature_data: Signature structure
 * @return ESP_OK if signature is valid, ESP_FAIL otherwise
 */
esp_err_t signature_verify_firmware(const uint8_t* firmware_data, 
                                   size_t firmware_size,
                                   const firmware_signature_t* signature_data);

/**
 * Calculate SHA256 hash of data
 * @param data: Input data
 * @param data_len: Length of input data
 * @param hash_output: Output buffer for hash (must be 32 bytes)
 * @return ESP_OK if successful
 */
esp_err_t signature_calculate_sha256(const uint8_t* data, size_t data_len, 
                                    uint8_t* hash_output);

/**
 * Verify RSA signature using public key
 * @param hash: SHA256 hash to verify
 * @param signature: RSA signature
 * @return ESP_OK if signature is valid
 */
esp_err_t signature_verify_rsa(const uint8_t* hash, const uint8_t* signature);

/**
 * Parse signature data from JSON response
 * @param json_response: JSON string containing signature info
 * @param signature_out: Output structure for signature data
 * @return ESP_OK if parsing successful
 */
esp_err_t signature_parse_from_json(const char* json_response, 
                                   firmware_signature_t* signature_out);

/**
 * Cleanup signature verification resources
 * Should be called on system shutdown
 */
void signature_cleanup(void);

#endif // FIRMWARE_SIGNATURE_H