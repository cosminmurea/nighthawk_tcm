#ifndef ENTROPY_H
#define ENTROPY_H

/** ----------------------------------------------------------------------------------
 * @brief   The functions defined in this file implement chaos-based entropy sourcing.
 * @details The chaotic systems used are seeded via /dev/urandom.
 * @author  Murea Cosmin Alexandru
 * @date    01.03.2024
 * ----------------------------------------------------------------------------------- **/

#include <stdlib.h>

/**
 * @brief   Generates a 128, 192 or 256-bit random seed using the bifurcation map.
 * @details Assumes that memory is already allocated for the seed buffer.
 * @param   seed        A buffer to hold the generated key.
 * @param   seed_len    The size of the seed in bytes (one of 16 / 24 / 32 ).
*/
void bm_generate_entropy(uint8_t* seed, size_t seed_len);

#endif