#ifndef SHA256_H
#define SHA256_H

/** ---------------------------------------------------------------------------------------
 * @brief   This file implements SHA2-256 adhering to the FIPS 180-4 specifications.
 * @details In the context of SHA2-256, a word refers to a 32-bit unsinged integer.
 * @author  Murea Cosmin Alexandru
 * @date    03.12.2023
 * ---------------------------------------------------------------------------------------- **/

#include <stdint.h>
#include <stddef.h>

/** ---------------------------------------------------------------------------------------
 * @brief   Hashes an array of bytes using SHA2-256.
 * @details The caller is responsible for freeing the memory allocated for the digest.
 * @param   data        A pointer to the data.
 * @param   data_len    The length of the data in bytes.
 * @param   padded      A NULL pointer for storing the digest as a word array.
 * ---------------------------------------------------------------------------------------- **/
void sha256(const uint8_t* data, size_t data_len, uint32_t** digest);

/** ---------------------------------------------------------------------------------------
 * @brief   Test the SHA2-256 implementation using the NIST test vectors.
 * @param   test_file   The path of the test file.
 * ---------------------------------------------------------------------------------------- **/
void sha256_testing(const char* test_file);

#endif