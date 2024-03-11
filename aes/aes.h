#ifndef AES_H
#define AES_H

/** ---------------------------------------------------------------------------------------
 * @brief   This file implements AES adhering to the FIPS 197 specifications.
 * @details The following key sizes are supported: 128 / 192 / 256.
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

/** ---------------------------------------------------------------------------------------
 * @brief   Encrypts a byte array using AES in CBC mode.
 * @details The caller is responsible for freeing the memory allocated for the ciphertext.
 * @param   plain       A pointer to the plaintext data.
 * @param   plain_len   The length of the plaintext in bytes.
 * @param   iv          A pointer to the initialisation vector IV.
 * @param   key         A pointer to the secret key.
 * @param   key_size    The size of the key used IN BYTES (use one of the 3 macros)!
 * @param   cipher      A NULL pointer for storing the ciphertext as a byte array.
 * @param   cipher_len  The length of the returned cipher in bytes.
 * ---------------------------------------------------------------------------------------- **/
void aes_cbc_encrypt(const uint8_t* plain, size_t plain_len, uint8_t* iv, uint8_t* key, uint8_t key_size, uint8_t** cipher, size_t* cipher_len);

/** ---------------------------------------------------------------------------------------
 * @brief   Decrypts a byte array using AES in CBC mode.
 * @details The caller is responsible for freeing the memory allocated for the plaintext.
 * @param   cipher      A pointer to the ciphertext data.
 * @param   cipher_len  The length of the ciphertext in bytes.
 * @param   iv          A pointer to the initialisation vector IV.
 * @param   key         A pointer to the secret key.
 * @param   key_size    The size of the key used IN BYTES (use one of the 3 macros)!
 * @param   plain       A NULL pointer for storing the plaintext as a byte array.
 * @param   plain_len   The length of the returned plaintext in bytes.
 * ---------------------------------------------------------------------------------------- **/
void aes_cbc_decrypt(const uint8_t* cipher, size_t cipher_len, uint8_t* iv, uint8_t* key, uint8_t key_size, uint8_t** plain, size_t* plain_len);

/** ---------------------------------------------------------------------------------------
 * @brief   Tests the CBC mode of operation using NIST test vectors for all key sizes.
 * @param   test_file   The relative path of the test file.
 * @param   key_size    The size of the key used IN BYTES (use one of the 3 macros)!
 * ---------------------------------------------------------------------------------------- **/
void aes_cbc_test(const char* test_file, uint8_t key_size);

#endif