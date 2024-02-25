#ifndef GENERAL_H
#define GENERAL_H

#include <stdlib.h>

// Input / Output
void print_bytes_hex(uint8_t* byte_array, size_t size);

// Memory management
void* safe_malloc(size_t size);

#endif