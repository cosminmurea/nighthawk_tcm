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

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

/** ---------------------------------------------------------------------------------------
 * @brief   Hashes an array of bytes using SHA2-256.
 * @details The caller is responsible for freeing the memory allocated for the digest.
 * @param   data        A pointer to the data.
 * @param   data_len    The length of the data in bytes.
 * @param   digest      A NULL pointer for storing the digest as a byte array.
 * ---------------------------------------------------------------------------------------- **/
void sha256(const uint8_t* data, size_t data_len, uint8_t** digest);

/** ---------------------------------------------------------------------------------------
 * @brief   Test the SHA2-256 implementation using the NIST short and long messages.
 * @param   test_file   The path of the test file.
 * ---------------------------------------------------------------------------------------- **/
void sha256_testing(const char* test_file);

/** ---------------------------------------------------------------------------------------
 * @brief   Test the SHA2-256 implementation using the NIST Monte Carlo test.
 * @param   test_file   The path of the test file.
 * ---------------------------------------------------------------------------------------- **/
void sha256_monte_carlo(const char* test_file);

#endif