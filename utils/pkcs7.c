#include <string.h>
#include "general.h"
#include "pkcs7.h"

void pkcs7_pad(const uint8_t* data, size_t data_len, uint8_t** padded, size_t* padded_len) {
    // Compute the padding byte;
    uint8_t padding_byte = PKCS7_BLOCK_SIZE - (data_len % PKCS7_BLOCK_SIZE);
    *padded_len = data_len + padding_byte;
    // Allocate memory for the padded data and copy the initial data;
    *padded = safe_malloc(*padded_len * sizeof **padded);
    memcpy(*padded, data, data_len);
    // Apply padding;
    for (uint8_t i = 0; i < padding_byte; i++) {
        (*padded)[data_len + i] = padding_byte;
    }
}

static uint8_t pkcs7_is_valid(const uint8_t* padded, size_t padded_len) {
    uint8_t padding_byte = padded[padded_len - 1];
    size_t data_len = padded_len - padding_byte;
    // Check if 1 < last byte <= PKCS7_BLOCK_SIZE;
    if (padding_byte < 1 || padding_byte > PKCS7_BLOCK_SIZE) {
        return 0;
    }
    // Check if all padding bytes match;
    for (uint8_t i = 0; i < padding_byte; i++) {
        if (padded[data_len + i] != padding_byte) {
            return 0;
        }
    }
    return 1;
}

void pkcs7_unpad(const uint8_t* padded, size_t padded_len, uint8_t** data, size_t* data_len) {
    // Check if the padding is valid PKCS7;
    if (!pkcs7_is_valid(padded, padded_len)) {
        return;
    }
    uint8_t padding_byte = padded[padded_len - 1];
    *data_len = padded_len - padding_byte;
    // Allocate memory for the unpadded data;
    *data = safe_malloc(*data_len * sizeof **data);
    memcpy(*data, padded, *data_len);
}