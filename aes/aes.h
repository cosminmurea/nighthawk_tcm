#ifndef AES_H
#define AES_H

/** ---------------------------------------------------------------------------------------
 * @brief   This file implements AES adhering to the FIPS 197 specifications.
 * @details The following key sizes (in bits) are supported: 128 / 192 / 256.
 * @author  Murea Cosmin Alexandru
 * @date    17.01.2023
 * ---------------------------------------------------------------------------------------- **/

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE 16
#define AES_WORD_SIZE 4
#define AES_KEY_SIZE_128 16
#define AES_KEY_SIZE_192 24
#define AES_KEY_SIZE_256 32

void aes_cbc_encrypt(const uint8_t* plain, size_t plain_len, uint8_t* iv, uint8_t* key, uint8_t key_size, uint8_t** cipher, size_t* cipher_len);
void aes_cbc_decrypt(const uint8_t* cipher, size_t cipher_len, uint8_t* iv, uint8_t* key, uint8_t key_size, uint8_t** plain, size_t* plain_len);
void aes_cbc_test(const char* test_file, uint8_t key_size);

#endif