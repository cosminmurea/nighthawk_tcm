#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define AES_BLOCK_SIZE 16
#define AES_WORD_SIZE 4
#define AES_KEY_SIZE_128 16
#define AES_KEY_SIZE_192 24
#define AES_KEY_SIZE_256 32

typedef struct aes_cbc_context aes_cbc_ctx;

uint8_t aes(uint8_t* data_block, uint8_t* cipher_block, uint8_t* key, uint8_t key_size, bool decrypt);
uint8_t* aes_cbc_encrypt(uint8_t* data, uint8_t* init_v, size_t data_length, uint8_t* key, uint8_t key_size);

#endif