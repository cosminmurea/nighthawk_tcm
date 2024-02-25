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

uint8_t* aes_cbc_encrypt(uint8_t* buffer, size_t buffer_length, uint8_t* iv, uint8_t* key, uint8_t key_size);
uint8_t* aes_cbc_decrypt(uint8_t* buffer, size_t buffer_length, uint8_t* iv, uint8_t* key, uint8_t key_size);

#endif