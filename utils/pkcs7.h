#ifndef PKCS7_H
#define PKCS7_H

// For uintW_t data types;
#include <stdint.h>
// For the size_t data type;
#include <stddef.h>
// For memcpy(), memset() and others;
#include <string.h>
// For the bool data type;
#include <stdbool.h>
// For safe_malloc();
#include "general.h"

// Opaque structures
typedef struct pkcs7_padding_context pkcs7_pad_ctx;
typedef struct pkcs7_unpadding_context pkcs7_unpad_ctx;

// Getters
uint8_t* pkcs7_get_padded(pkcs7_pad_ctx* pad_ctx);
size_t pkcs7_get_padded_length(pkcs7_pad_ctx* pad_ctx);
uint8_t* pkcs7_get_unpadded(pkcs7_unpad_ctx* unpad_ctx);
size_t pkcs7_get_unpadded_length(pkcs7_unpad_ctx* unpad_ctx);

// PKCS7 padding functions
pkcs7_pad_ctx* pkcs7_pad(const uint8_t* data, size_t data_length, uint8_t block_size);
pkcs7_unpad_ctx* pkcs7_unpad(pkcs7_pad_ctx* pad_ctx, uint8_t block_size);
void pkcs7_destroy(pkcs7_pad_ctx* pad_ctx, pkcs7_unpad_ctx* unpad_ctx);

#endif