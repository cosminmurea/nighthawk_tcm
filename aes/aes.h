#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE 16
#define AES_WORD_SIZE 4
#define AES_KEY_SIZE_128 16
#define AES_KEY_SIZE_192 24
#define AES_KEY_SIZE_256 32

typedef struct aes_cbc_context aes_cbc_ctx;

// Should iv and key be const as well?
aes_cbc_ctx* aes_cbc_encrypt(const uint8_t* plain, size_t plain_length, uint8_t* iv, uint8_t* key, uint8_t key_size);
aes_cbc_ctx* aes_cbc_decrypt(const uint8_t* cipher, size_t cipher_length, uint8_t* iv, uint8_t* key, uint8_t key_size);
void aes_cbc_destroy(aes_cbc_ctx* ctx);

uint8_t* aes_cbc_get_cipher(aes_cbc_ctx* ctx);
uint8_t* aes_cbc_get_plain(aes_cbc_ctx* ctx);
size_t aes_cbc_get_cipher_length(aes_cbc_ctx* ctx);
size_t aes_cbc_get_plain_length(aes_cbc_ctx* ctx);

#endif