#ifndef GENERAL_H
#define GENERAL_H

/** ----------------------------------------------------------------------------------
 * @brief   The utility functions defined in this file are used across all files.
 * @author  Murea Cosmin Alexandru
 * @date    27.02.2024
 * ----------------------------------------------------------------------------------- **/

#include <stdlib.h>
#include <stdio.h>

/** ----------------------------------------------------------------------------------
 * @brief   Prints an array of bytes to stdout in hex format.
 * @param   byte_array    A pointer to the array of bytes to print.
 * @param   size          The number of bytes to print.
 * ----------------------------------------------------------------------------------- **/
void print_byte_array(const uint8_t* byte_array, size_t size);

/** ----------------------------------------------------------------------------------
 * @brief   Converts a hex string into an array of bytes.
 * @details If the length of the hex string is odd, a 0 nibble is prepended.
 * @param   hex_string  A pointer to the hex string to convert.
 * @param   hex_len     The number of hex digits in the string.
 * @returns A pointer to the byte array.
 * ----------------------------------------------------------------------------------- **/
uint8_t* hex_to_byte_array(const char* hex_string, size_t hex_len);

/** ----------------------------------------------------------------------------------
 * @brief   Convert an array of byte into a uint64_t value.
 * @param   byte_array    A pointer to the array of bytes to convert.
 * @param   size          The size of the byte array.
 * @returns A 64 bit value where each byte is an array element.
 * ----------------------------------------------------------------------------------- **/
uint64_t byte_array_to_uint64(const uint8_t* byte_array);

/** ----------------------------------------------------------------------------------
 * @brief   Wraps the malloc() function and handles memory allocation errors.
 * @param   size        The amount of heap memory to allocate (in bytes).
 * @returns A pointer to the block of memory allocated (if no errors occurred).
 * ----------------------------------------------------------------------------------- **/
void* safe_malloc(size_t size);

/** ----------------------------------------------------------------------------------
 * @brief   Wraps the fopen() function and handles file access errors.
 * @param   file_path   The path of the file to open.
 * @param   mode        The mode in which to open the file.
 * @returns A pointer to the open file (if no errors occurred).
 * ----------------------------------------------------------------------------------- **/
FILE* safe_fopen(const char* file_path, const char* mode);

/** ----------------------------------------------------------------------------------
 * @brief   Reads a file into an array of bytes.
 * @param   file_path   The path of the file to read.
 * @param   buffer      A NULL pointer for storing the file data as a byte array.
 * @param   buffer_len  The length of the buffer in bytes.
 * ----------------------------------------------------------------------------------- **/
void file_to_byte_array(const char* file_path, uint8_t** buffer, size_t* buffer_len);

/** ----------------------------------------------------------------------------------
 * @brief   Converts a uint32_t value from little-endian to big-endian.
 * @param   value       The value to be converted.
 * @returns A big-endian uint32_t value.
 * ----------------------------------------------------------------------------------- **/
uint32_t ltb_endian_conv32(uint32_t value);

#endif