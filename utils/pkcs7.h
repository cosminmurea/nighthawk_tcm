#ifndef PKCS7_H
#define PKCS7_H

#include <stdint.h>
#include <stddef.h>

typedef struct pkcs7_padding_context pkcs7_pad_ctx;
typedef struct pkcs7_unpadding_context pkcs7_unpad_ctx;

uint8_t* pkcs7_get_padded(pkcs7_pad_ctx* pad_ctx);
size_t pkcs7_get_padded_length(pkcs7_pad_ctx* pad_ctx);
uint8_t* pkcs7_get_unpadded(pkcs7_unpad_ctx* unpad_ctx);
size_t pkcs7_get_unpadded_length(pkcs7_unpad_ctx* unpad_ctx);

pkcs7_pad_ctx* pkcs7_pad(const uint8_t* data, size_t data_length, uint8_t block_size);
pkcs7_unpad_ctx* pkcs7_unpad(const uint8_t* padded_data, size_t padded_length);
void pkcs7_destroy_pad_ctx(pkcs7_pad_ctx* pad_ctx);
void pkcs7_destroy_unpad_ctx(pkcs7_unpad_ctx* unpad_ctx);

#endif