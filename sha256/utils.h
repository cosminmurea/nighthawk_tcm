#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

void read_file_bytes(const char* file_path, uint8_t** buffer, size_t* file_length);

#endif