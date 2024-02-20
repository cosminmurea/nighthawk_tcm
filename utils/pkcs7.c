#include "pkcs7.h"

struct pkcs7_padding_context {
    uint8_t* padded_data;
    size_t padded_data_length;
    uint8_t padding_byte;
};

struct pkcs7_unpadding_context {
    uint8_t* data;
    size_t data_length;
    uint8_t padding_byte;
};

uint8_t* pkcs7_get_padded(pkcs7_pad_ctx* pad_ctx) {
    return pad_ctx->padded_data;
}

size_t pkcs7_get_padded_length(pkcs7_pad_ctx* pad_ctx) {
    return pad_ctx->padded_data_length;
}

uint8_t* pkcs7_get_unpadded(pkcs7_unpad_ctx* unpad_ctx) {
    return unpad_ctx->data;
}

size_t pkcs7_get_unpadded_length(pkcs7_unpad_ctx* unpad_ctx) {
    return unpad_ctx->data_length;
}

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
    pad_ctx->padding_byte = block_size - (data_length % block_size);
    // Length of the data with padding;
    pad_ctx->padded_data_length = data_length + pad_ctx->padding_byte;
    // Allocate memory for byte array containing the padded data;
    pad_ctx->padded_data = safe_malloc(pad_ctx->padded_data_length * sizeof *(pad_ctx->padded_data));
    // Set all entries to 0;
    memset(pad_ctx->padded_data, 0, pad_ctx->padded_data_length);
    // Copy the initial data into the padded data array;
    memcpy(pad_ctx->padded_data, data, data_length);
    // Pad the rest of the array up to a multiple of the block size;
    for (uint8_t i = 0; i < pad_ctx->padding_byte; i++) {
        pad_ctx->padded_data[data_length + i] = pad_ctx->padding_byte;
    }
    return pad_ctx;
}

static bool pkcs7_validate_padding(pkcs7_pad_ctx* pad_ctx) {
    size_t data_length = pad_ctx->padded_data_length - pad_ctx->padding_byte;
    uint8_t expected_byte = pad_ctx->padding_byte;
    // Check if the last element is equal to the padding byte;
    if (pad_ctx->padded_data[pad_ctx->padded_data_length - 1] != expected_byte) {
        return false;
    }
    // Check if the rest of the padding bytes are valid;
    for (uint8_t i = 0; i < pad_ctx->padding_byte; i++) {
        if (pad_ctx->padded_data[data_length + i] != expected_byte) {
            return false;
        }
    }
    return true;
}

pkcs7_unpad_ctx* pkcs7_unpad(pkcs7_pad_ctx* pad_ctx, uint8_t block_size) {
    // Returns NULL if the padding is not valid;
    if (!pkcs7_validate_padding(pad_ctx)) {
        return NULL;
    }
    // Allocate memory for the padding context;
    pkcs7_unpad_ctx* unpad_ctx = safe_malloc(sizeof *unpad_ctx);
    unpad_ctx->padding_byte = pad_ctx->padding_byte;
    // Length of the data without padding;
    unpad_ctx->data_length = pad_ctx->padded_data_length - pad_ctx->padding_byte;
    // Allocate memory for byte array containing the unpadded data;
    unpad_ctx->data = safe_malloc(unpad_ctx->data_length * sizeof *(unpad_ctx->data));
    // Copy the stripped data into the data array;
    memcpy(unpad_ctx->data, pad_ctx->padded_data, unpad_ctx->data_length);
    return unpad_ctx;
}

void pkcs7_destroy(pkcs7_pad_ctx* pad_ctx, pkcs7_unpad_ctx* unpad_ctx) {
    // Free
    //  - The padded data array followed by the padding context;
    free(pad_ctx->padded_data);
    free(pad_ctx);
    //  - The data array followed by the unpadding context;
    free(unpad_ctx->data);
    free(unpad_ctx);
}