// For memcpy(), memset() and others;
#include <string.h>
// For the bool data type;
#include <stdbool.h>
// For safe_malloc();
#include "general.h"
#include "pkcs7.h"

struct pkcs7_padding_context {
    uint8_t* padded_data;
    size_t padded_length;
};

struct pkcs7_unpadding_context {
    uint8_t* data;
    size_t data_length;
};

uint8_t* pkcs7_get_padded(pkcs7_pad_ctx* pad_ctx) {
    return pad_ctx->padded_data;
}

size_t pkcs7_get_padded_length(pkcs7_pad_ctx* pad_ctx) {
    return pad_ctx->padded_length;
}

uint8_t* pkcs7_get_unpadded(pkcs7_unpad_ctx* unpad_ctx) {
    return unpad_ctx->data;
}

size_t pkcs7_get_unpadded_length(pkcs7_unpad_ctx* unpad_ctx) {
    return unpad_ctx->data_length;
}

// Returns NULL if an invalid block size is provided;
// It's the callers responsability to free the padding context memory;
pkcs7_pad_ctx* pkcs7_pad(const uint8_t* data, size_t data_length, uint8_t block_size) {
    // Only 16 and 32 byte blocks are supported;
    if (block_size != 16 && block_size != 32) {
        // INVALID BLOCK SIZE
        return NULL;
    }
    // Allocate memory for the padding context;
    pkcs7_pad_ctx* pad_ctx = safe_malloc(sizeof *pad_ctx);
    // The padding byte is the amount of bytes added;
    // If data = 10 bytes and the block size is 16, 6 bytes of value 0x06 will be appended;
    uint8_t padding_byte =  block_size - (data_length % block_size);
    // Length of the data with padding;
    pad_ctx->padded_length = data_length + padding_byte;
    // Allocate memory for byte array containing the padded data;
    pad_ctx->padded_data = safe_malloc(pad_ctx->padded_length * sizeof *(pad_ctx->padded_data));
    // Set all entries to 0;
    memset(pad_ctx->padded_data, 0, pad_ctx->padded_length);
    // Copy the initial data into the padded data array;
    memcpy(pad_ctx->padded_data, data, data_length);
    // Pad the rest of the array up to a multiple of the block size;
    for (uint8_t i = 0; i < padding_byte; i++) {
        pad_ctx->padded_data[data_length + i] = padding_byte;
    }
    return pad_ctx;
}

static bool pkcs7_validate_padding(const uint8_t* padded_data, size_t padded_length) {
    uint8_t padding_byte = padded_data[padded_length - 1];
    size_t data_length = padded_length - padding_byte;
    // Check if the last byte is in the expected range (1 < byte < N where N is the block size in bytes);
    if (padding_byte < 1 || padding_byte > 32) {
        return false;
    }
    // Check if all padding bytes match;
    for (uint8_t i = 0; i < padding_byte; i++) {
        if (padded_data[data_length + i] != padding_byte) {
            return false;
        }
    }
    return true;
}

// Returns NULL if the padding is invalid;
// It's the callers responsability to free the unpadding context memory;
pkcs7_unpad_ctx* pkcs7_unpad(const uint8_t* padded_data, size_t padded_length) {
    // Returns NULL if the padding is not valid;
    if (!pkcs7_validate_padding(padded_data, padded_length)) {
        return NULL;
    }
    // Allocate memory for the padding context;
    pkcs7_unpad_ctx* unpad_ctx = safe_malloc(sizeof *unpad_ctx);
    uint8_t padding_byte = padded_data[padded_length - 1];
    // Length of the data without padding;
    unpad_ctx->data_length = padded_length - padding_byte;
    // Allocate memory for byte array containing the unpadded data;
    unpad_ctx->data = safe_malloc(unpad_ctx->data_length * sizeof *(unpad_ctx->data));
    // Copy the stripped data into the data array;
    memcpy(unpad_ctx->data, padded_data, unpad_ctx->data_length);
    return unpad_ctx;
}

void pkcs7_destroy_pad_ctx(pkcs7_pad_ctx* pad_ctx) {
    // Free the padded data array followed by the padding context;
    free(pad_ctx->padded_data);
    free(pad_ctx);
}

void pkcs7_destroy_unpad_ctx(pkcs7_unpad_ctx* unpad_ctx) {
    //Free the data array followed by the unpadding context;
    free(unpad_ctx->data);
    free(unpad_ctx);
}