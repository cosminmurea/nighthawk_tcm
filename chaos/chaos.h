#ifndef CHAOS_H
#define CHAOS_H

/** ----------------------------------------------------------------------------------
 * @brief   The functions defined in this file implement chaos-based entropy sourcing.
 * @details The chaotic systems used are seeded via /dev/urandom.
 * @author  Murea Cosmin Alexandru
 * @date    01.03.2024
 * ----------------------------------------------------------------------------------- **/

#include <stdlib.h>

/** ---------------------------------------------------------------------------------------
 * @brief   Generate random bytes.
 * @param   key         An array to hold the generated key.
 * @param   key_len     The length of the key to be generated in bytes.
 * ---------------------------------------------------------------------------------------- **/
void generate_entropy(uint8_t* key, size_t key_len);

/** ---------------------------------------------------------------------------------------
 * @brief   Computes the Shannon entropy of a system for a given sample.
 * @param   sample      The sample to be tested.
 * @param   sample_len  The length of the sample in bytes.
 * ---------------------------------------------------------------------------------------- **/
double shannon_entropy(uint8_t* sample, size_t sample_len);

/** ---------------------------------------------------------------------------------------
 * @brief   Computes the Lyapunov exponent of the logistics map for a given parameter r.
 * @param   r           0 <= r <= 4.
 * ---------------------------------------------------------------------------------------- **/
double lm_lyapunov_exp(double r);

/** ---------------------------------------------------------------------------------------
 * @brief   Computes the Lyapunov exponent of the tent map for a given parameter r.
 * @param   r           0 <= r <= 2.
 * ---------------------------------------------------------------------------------------- **/
double tent_lyapunov_exp(double r);

/** ---------------------------------------------------------------------------------------
 * @brief   Computes the Lyapunov exponent of the sine map for a given parameter r.
 * @param   r           0 <= r <= 1.
 * ---------------------------------------------------------------------------------------- **/
double sine_lyapunov_exp(double r);

#endif