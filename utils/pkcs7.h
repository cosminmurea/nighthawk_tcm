#ifndef PKCS7_H
#define PKCS7_H

/** ---------------------------------------------------------------------------------------
 * @brief   This file implements functions pertaining to PKCS7 padding and unpadding.
 * @author  Murea Cosmin Alexandru
 * @date    28.02.2024
 * ---------------------------------------------------------------------------------------- **/

#include <stdint.h>
#include <stddef.h>

/** ---------------------------------------------------------------------------------------
 * @brief   Pads data using the PKCS7 padding scheme.
 * @details The caller is responsible for freeing the memory allocated for the padded data.
 * @param   data        A pointer to the unpadded data.
 * @param   data_len    The length of the unpadded data.
 * @param   padded      A NULL pointer for storing the padded data.
 * @param   padded_len  The length of the returned padded data.
 * ---------------------------------------------------------------------------------------- **/
void pkcs7_pad(const uint8_t* data, size_t data_len, uint8_t** padded, size_t* padded_len);

/** ---------------------------------------------------------------------------------------
 * @brief   Unpads data using the PKCS7 unpadding scheme.
 * @details The caller is responsible for freeing the memory allocated for the unpadded data.
 * @param   padded      A pointer to the padded data.
 * @param   padded_len  The length of the padded data.
 * @param   data        A NULL pointer for storing the unpadded data.
 * @param   data_len    The length of the unpadded data.
 * ---------------------------------------------------------------------------------------- **/
void pkcs7_unpad(const uint8_t* padded, size_t padded_len, uint8_t** data, size_t* data_len);

#endif