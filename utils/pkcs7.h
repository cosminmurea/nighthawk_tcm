#ifndef PKCS7_H
#define PKCS7_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "general.h"

typedef struct {
    uint8_t* data;
    uint8_t* padded_data;
    size_t data_length;
    size_t padded_data_length;
    uint8_t padding_byte;
    uint8_t block_size;
} pkcs7_context;

pkcs7_context* pkcs7_context_init(const uint8_t* data, size_t data_length, uint8_t block_size);
void pkcs7_pad(pkcs7_context* context);
pkcs7_context* pkcs7_unpad(uint8_t* padded_data, size_t padded_data_length, uint8_t block_size);
void pkcs7_context_destroy(pkcs7_context* context);

#endif