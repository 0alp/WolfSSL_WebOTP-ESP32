#include "firmware_signature.h"
#include "esp_log.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <string.h>
#include <cJSON.h>

static const char *TAG = "FIRMWARE_SIGNATURE";

// Global variables for signature verification
static RsaKey g_rsa_key;
static bool g_signature_initialized = false;

// Hardcoded public key (in production, this should be stored securely)
static const char* g_public_key_pem = 
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2Z8QX1vqFQI5uY+8YpTF\n"
"7LKxJ3mVQs8hGk2xJ9nP7Mq5wX2vF8pR4K3tL6nQ9sR5hY2mK7jD1vN9xW4eA8zT\n"
"6oU3bV9fJ2kH5rY8nQ4pL1mW9xS3zK7dF4vG2hJ8qR5tL6nQ9sR5hY2mK7jD1vN9\n"
"xW4eA8zT6oU3bV9fJ2kH5rY8nQ4pL1mW9xS3zK7dF4vG2hJ8qR5tL6nQ9sR5hY2m\n"
"K7jD1vN9xW4eA8zT6oU3bV9fJ2kH5rY8nQ4pL1mW9xS3zK7dF4vG2hJ8qR5tL6nQ\n"
"9sR5hY2mK7jD1vN9xW4eA8zT6oU3bV9fJ2kH5rY8nQ4pL1mW9xS3zK7dF4vG2hJ8\n"
"qR5tL6nQ9sR5hY2mK7jD1vN9xW4eA8zT6oU3bV9fJ2kH5rY8nQ4pL1mW9xS3zK7d\n"
"QIDAQAB\n"
"-----END PUBLIC KEY-----";

esp_err_t signature_init(const char* public_key_pem)
{
    if (g_signature_initialized) {
        ESP_LOGW(TAG, "Signature verification already initialized");
        return ESP_OK;
    }
    
    ESP_LOGI(TAG, "Initializing WolfSSL firmware signature verification...");
    
    // Initialize WolfSSL RSA key
    int ret = wc_InitRsaKey(&g_rsa_key, NULL);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to initialize RSA key: %d", ret);
        return ESP_FAIL;
    }
    
    // Use provided key or default hardcoded key
    const char* key_to_use = public_key_pem ? public_key_pem : g_public_key_pem;
    
    // Parse PEM formatted public key
    word32 idx = 0;
    byte der_buffer[2048];
    word32 der_size = sizeof(der_buffer);
    
    // Convert PEM to DER format using WolfSSL
    ret = wc_CertPemToDer((const unsigned char*)key_to_use, strlen(key_to_use), 
                         der_buffer, der_size, PUBLICKEY_TYPE);
    if (ret < 0) {
        ESP_LOGE(TAG, "Failed to convert PEM to DER: %d", ret);
        wc_FreeRsaKey(&g_rsa_key);
        return ESP_FAIL;
    }
    der_size = ret;
    
    // Import RSA public key from DER using WolfSSL
    ret = wc_RsaPublicKeyDecode(der_buffer, &idx, &g_rsa_key, der_size);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to decode RSA public key: %d", ret);
        wc_FreeRsaKey(&g_rsa_key);
        return ESP_FAIL;
    }
    
    g_signature_initialized = true;
    ESP_LOGI(TAG, "WolfSSL firmware signature verification initialized successfully");
    
    return ESP_OK;
}

esp_err_t signature_calculate_sha256(const uint8_t* data, size_t data_len, 
                                    uint8_t* hash_output)
{
    if (!data || !hash_output) {
        ESP_LOGE(TAG, "Invalid parameters for SHA256 calculation");
        return ESP_ERR_INVALID_ARG;
    }
    
    wc_Sha256 sha256;
    int ret = wc_InitSha256(&sha256);
    if (ret != 0) {
        ESP_LOGE(TAG, "WolfSSL SHA256 initialization failed: %d", ret);
        return ESP_FAIL;
    }
    
    ret = wc_Sha256Update(&sha256, data, data_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "WolfSSL SHA256 update failed: %d", ret);
        wc_Sha256Free(&sha256);
        return ESP_FAIL;
    }
    
    ret = wc_Sha256Final(&sha256, hash_output);
    if (ret != 0) {
        ESP_LOGE(TAG, "WolfSSL SHA256 finalization failed: %d", ret);
        wc_Sha256Free(&sha256);
        return ESP_FAIL;
    }
    
    wc_Sha256Free(&sha256);
    
    ESP_LOGD(TAG, "SHA256 calculated successfully using WolfSSL");
    return ESP_OK;
}

esp_err_t signature_verify_rsa(const uint8_t* hash, const uint8_t* signature)
{
    if (!g_signature_initialized) {
        ESP_LOGE(TAG, "Signature verification not initialized");
        return ESP_FAIL;
    }
    
    if (!hash || !signature) {
        ESP_LOGE(TAG, "Invalid parameters for RSA verification");
        return ESP_ERR_INVALID_ARG;
    }
    
    ESP_LOGI(TAG, "Verifying RSA signature using WolfSSL...");
    
    byte decrypted_hash[RSA_SIGNATURE_SIZE];
    int decrypted_len;
    
    // Decrypt signature using public key (RSA signature verification) with WolfSSL
    decrypted_len = wc_RsaSSL_Verify(signature, RSA_SIGNATURE_SIZE, 
                                    decrypted_hash, sizeof(decrypted_hash), 
                                    &g_rsa_key);
    
    if (decrypted_len < 0) {
        ESP_LOGE(TAG, "WolfSSL RSA signature verification failed: %d", decrypted_len);
        return ESP_FAIL;
    }
    
    // For PKCS#1 v1.5 padding, we need to parse the decrypted data
    // The decrypted data should contain ASN.1 DigestInfo structure
    // For SHA256, it should start with: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
    
    const byte sha256_digest_info[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20
    };
    
    if (decrypted_len < (sizeof(sha256_digest_info) + SHA256_HASH_SIZE)) {
        ESP_LOGE(TAG, "Decrypted signature too short: %d bytes", decrypted_len);
        return ESP_FAIL;
    }
    
    // Verify DigestInfo header
    if (memcmp(decrypted_hash, sha256_digest_info, sizeof(sha256_digest_info)) != 0) {
        ESP_LOGE(TAG, "Invalid DigestInfo in signature");
        return ESP_FAIL;
    }
    
    // Compare the hash
    byte* signature_hash = decrypted_hash + sizeof(sha256_digest_info);
    if (memcmp(hash, signature_hash, SHA256_HASH_SIZE) != 0) {
        ESP_LOGE(TAG, "Hash mismatch in signature verification");
        
        ESP_LOGE(TAG, "Expected hash:");
        esp_log_buffer_hex(TAG, hash, SHA256_HASH_SIZE);
        ESP_LOGE(TAG, "Signature hash:");
        esp_log_buffer_hex(TAG, signature_hash, SHA256_HASH_SIZE);
        
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "WolfSSL RSA signature verification successful");
    return ESP_OK;
}

esp_err_t signature_parse_from_json(const char* json_response, 
                                   firmware_signature_t* signature_out)
{
    if (!json_response || !signature_out) {
        ESP_LOGE(TAG, "Invalid parameters for JSON parsing");
        return ESP_ERR_INVALID_ARG;
    }
    
    cJSON *json = cJSON_Parse(json_response);
    if (!json) {
        ESP_LOGE(TAG, "Failed to parse JSON response");
        return ESP_FAIL;
    }
    
    esp_err_t result = ESP_OK;
    
    // Parse signature (base64 encoded)
    cJSON *signature_item = cJSON_GetObjectItem(json, "signature");
    if (!signature_item || !cJSON_IsString(signature_item)) {
        ESP_LOGE(TAG, "Missing or invalid signature in JSON");
        result = ESP_FAIL;
        goto cleanup;
    }
    
    // Decode base64 signature using WolfSSL
    word32 signature_len = RSA_SIGNATURE_SIZE;
    int ret = Base64_Decode((const byte*)cJSON_GetStringValue(signature_item),
                           strlen(cJSON_GetStringValue(signature_item)),
                           signature_out->signature,
                           &signature_len);
    if (ret != 0 || signature_len != RSA_SIGNATURE_SIZE) {
        ESP_LOGE(TAG, "WolfSSL failed to decode signature from base64: %d", ret);
        result = ESP_FAIL;
        goto cleanup;
    }
    
    // Parse hash (base64 encoded)
    cJSON *hash_item = cJSON_GetObjectItem(json, "hash");
    if (!hash_item || !cJSON_IsString(hash_item)) {
        ESP_LOGE(TAG, "Missing or invalid hash in JSON");
        result = ESP_FAIL;
        goto cleanup;
    }
    
    // Decode base64 hash using WolfSSL
    word32 hash_len = SHA256_HASH_SIZE;
    ret = Base64_Decode((const byte*)cJSON_GetStringValue(hash_item),
                       strlen(cJSON_GetStringValue(hash_item)),
                       signature_out->hash,
                       &hash_len);
    if (ret != 0 || hash_len != SHA256_HASH_SIZE) {
        ESP_LOGE(TAG, "WolfSSL failed to decode hash from base64: %d", ret);
        result = ESP_FAIL;
        goto cleanup;
    }
    
    // Parse firmware size
    cJSON *size_item = cJSON_GetObjectItem(json, "firmware_size");
    if (!size_item || !cJSON_IsNumber(size_item)) {
        ESP_LOGE(TAG, "Missing or invalid firmware_size in JSON");
        result = ESP_FAIL;
        goto cleanup;
    }
    signature_out->firmware_size = (uint32_t)cJSON_GetNumberValue(size_item);
    
    // Parse version
    cJSON *version_item = cJSON_GetObjectItem(json, "version");
    if (!version_item || !cJSON_IsString(version_item)) {
        ESP_LOGE(TAG, "Missing or invalid version in JSON");
        result = ESP_FAIL;
        goto cleanup;
    }
    strncpy(signature_out->version, cJSON_GetStringValue(version_item), 
            sizeof(signature_out->version) - 1);
    signature_out->version[sizeof(signature_out->version) - 1] = '\0';
    
    // Parse timestamp
    cJSON *timestamp_item = cJSON_GetObjectItem(json, "timestamp");
    if (!timestamp_item || !cJSON_IsNumber(timestamp_item)) {
        ESP_LOGE(TAG, "Missing or invalid timestamp in JSON");
        result = ESP_FAIL;
        goto cleanup;
    }
    signature_out->timestamp = (uint32_t)cJSON_GetNumberValue(timestamp_item);
    
    ESP_LOGI(TAG, "Signature data parsed successfully using WolfSSL - Version: %s, Size: %u bytes", 
             signature_out->version, signature_out->firmware_size);

cleanup:
    cJSON_Delete(json);
    return result;
}

esp_err_t signature_verify_firmware(const uint8_t* firmware_data, 
                                   size_t firmware_size,
                                   const firmware_signature_t* signature_data)
{
    if (!firmware_data || !signature_data) {
        ESP_LOGE(TAG, "Invalid parameters for firmware verification");
        return ESP_ERR_INVALID_ARG;
    }
    
    if (!g_signature_initialized) {
        ESP_LOGE(TAG, "Signature verification not initialized");
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "Starting WolfSSL firmware signature verification...");
    ESP_LOGI(TAG, "Firmware size: %zu bytes", firmware_size);
    ESP_LOGI(TAG, "Expected size: %u bytes", signature_data->firmware_size);
    ESP_LOGI(TAG, "Version: %s", signature_data->version);
    
    // Verify firmware size
    if (firmware_size != signature_data->firmware_size) {
        ESP_LOGE(TAG, "Firmware size mismatch: expected %u, got %zu", 
                 signature_data->firmware_size, firmware_size);
        return ESP_FAIL;
    }
    
    // Calculate SHA256 hash of firmware using WolfSSL
    uint8_t calculated_hash[SHA256_HASH_SIZE];
    esp_err_t ret = signature_calculate_sha256(firmware_data, firmware_size, calculated_hash);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to calculate firmware hash with WolfSSL");
        return ret;
    }
    
    // Compare calculated hash with expected hash
    if (memcmp(calculated_hash, signature_data->hash, SHA256_HASH_SIZE) != 0) {
        ESP_LOGE(TAG, "Firmware hash mismatch - firmware corrupted or tampered");
        
        // Log hashes for debugging
        ESP_LOGE(TAG, "Expected hash:");
        esp_log_buffer_hex(TAG, signature_data->hash, SHA256_HASH_SIZE);
        ESP_LOGE(TAG, "Calculated hash:");
        esp_log_buffer_hex(TAG, calculated_hash, SHA256_HASH_SIZE);
        
        return ESP_FAIL;
    }
    
    // Verify RSA signature using WolfSSL
    ret = signature_verify_rsa(calculated_hash, signature_data->signature);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "WolfSSL RSA signature verification failed");
        return ret;
    }
    
    ESP_LOGI(TAG, "WolfSSL firmware signature verification completed successfully");
    ESP_LOGI(TAG, "Firmware is authentic and untampered");
    
    return ESP_OK;
}

// Cleanup function (should be called on shutdown)
void signature_cleanup(void)
{
    if (g_signature_initialized) {
        wc_FreeRsaKey(&g_rsa_key);
        g_signature_initialized = false;
        ESP_LOGI(TAG, "WolfSSL signature verification resources freed");
    }
}