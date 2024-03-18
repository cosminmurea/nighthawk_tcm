#ifndef RSA_H
#define RSA_H

/** ---------------------------------------------------------------------------------------
 * @brief   This file implements RSA using the GNU Multiple Precision Arithmetic Library.
 * @author  Murea Cosmin Alexandru
 * @date    17.03.2024
 * ---------------------------------------------------------------------------------------- **/

#include <stdlib.h>
#include <gmp.h>

/**
 * @details The two primes p and q should be half of the modulus in length.
 * Since multiplying two 512 bit numbers can result in a 1023 bit product, we set the
 * first two bits of p and q to 1. This way, a 1024 bit product is guaranteed.
*/

/** ---------------------------------------------------------------------------------------
 * @brief   Generates an RSA decryption key.
 * @param   p       A big prime number at least 512 bits long.
 * @param   q       Another big prime number, same length requirement as for p.
 * @param   enc     The encryption key.
 * @param   n
 * @param   dec
 * ---------------------------------------------------------------------------------------- **/
// void rsa_generate_decryption_key(const mpz_t p, const mpz_t q, const mpz_t enc_key, mpz_t n, mpz_t dec_key);

void rsa(const uint8_t* data_string, const size_t data_len, const char* p_string, const char* q_string, const char* enc_key_string);

#endif