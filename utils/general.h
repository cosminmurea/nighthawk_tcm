#ifndef GENERAL_H
#define GENERAL_H

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

void print_bytes_hex(uint8_t* byte_array, size_t size);
void* safe_malloc(size_t size);

#endif