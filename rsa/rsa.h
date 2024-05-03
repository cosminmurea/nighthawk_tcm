#ifndef RSA_H
#define RSA_H

/** ---------------------------------------------------------------------------------------
 * @brief   This file implements RSA using the GNU Multiple Precision Arithmetic Library.
 * @author  Murea Cosmin Alexandru
 * @date    17.03.2024
 * ---------------------------------------------------------------------------------------- **/

#include <stdlib.h>
#include <gmp.h>

void rsa(const uint8_t* data_string, const size_t data_len, const char* p_string, const char* q_string, const char* enc_key_string);

#endif