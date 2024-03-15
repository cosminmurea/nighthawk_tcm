#ifndef ENTROPY_H
#define ENTROPY_H

/** ----------------------------------------------------------------------------------
 * @brief   The functions defined in this file implement chaos-based entropy sourcing.
 * @details The chaotic systems used are seeded via /dev/urandom.
 * @author  Murea Cosmin Alexandru
 * @date    01.03.2024
 * ----------------------------------------------------------------------------------- **/

#include <stdlib.h>

/** ---------------------------------------------------------------------------------------
 * @brief   Generate random bytes using the logistics map with r = 4.
 * @param   key         An array to hold the generated key.
 * @param   key_len     The length of the key to be generated in bytes.
 * ---------------------------------------------------------------------------------------- **/
void lm_generate_entropy(uint8_t* key, size_t key_len);

/** ---------------------------------------------------------------------------------------
 * @brief   Computes the Shannon entropy of a system for a given sample.
 * @param   sample      The sample to be tested.
 * @param   sample_len  The length of the sample in bytes.
 * ---------------------------------------------------------------------------------------- **/
double shannon_entropy(uint8_t* sample, size_t sample_len);

#endif