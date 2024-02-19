#include "pkcs7.h"

pkcs7_context* pkcs7_context_init(const uint8_t* data, size_t data_length, uint8_t block_size) {
    if (block_size != 16 && block_size != 32) {
        // INVALID BLOCK SIZE
        return NULL;
    }

    pkcs7_context* context = safe_malloc(sizeof *context);

    context->block_size = block_size;
    context->padding_byte = block_size - (data_length % block_size);
    context->padded_data_length = data_length + context->padding_byte;

    context->data_length = data_length;
    context->data = safe_malloc(data_length * sizeof *(context->data));
    memcpy(context->data, data, data_length);

    context->padded_data = safe_malloc(context->padded_data_length * sizeof *(context->padded_data));
    memset(context->padded_data, 0, context->padded_data_length);
    memcpy(context->padded_data, data, data_length);

    return context;
}

void pkcs7_pad(pkcs7_context* context) {
    for (uint8_t i = 0; i < context->padding_byte; i++) {
        context->padded_data[context->data_length + i] = context->padding_byte;
    }
}

pkcs7_context* pkcs7_unpad(uint8_t* padded_data, size_t padded_data_length, uint8_t block_size) {
    uint8_t padding_byte = padded_data[padded_data_length - 1];
    size_t data_length = padded_data_length - padding_byte;
    pkcs7_context* context = pkcs7_context_init(padded_data, data_length, block_size);
    return context;
}

void pkcs7_context_destroy(pkcs7_context* context) {
    free(context->data);
    free(context->padded_data);
    free(context);
}