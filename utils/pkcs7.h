#ifndef PKCS7_H
#define PKCS7_H

/**
 * Implementation of PKCS7 padding. The only supported block size is 16 bytes / 128 bits.
*/

#include <stdint.h>
#include <stddef.h>

#define PKCS7_BLOCK_SIZE 16

// The 'padded' pointer should be initialized with NULL and its address passed.
// It is the callers responsability to free the memory allocated for the buffer.
void pkcs7_pad(const uint8_t* data, size_t data_len, uint8_t** padded, size_t* padded_len);

// The 'data' pointer should be initialized with NULL and its address passed.
// It is the callers responsability to free the memory allocated for the buffer.
void pkcs7_unpad(const uint8_t* padded, size_t padded_len, uint8_t** data, size_t* data_len);

#endif