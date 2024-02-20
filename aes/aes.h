#ifndef AES_H
#define AES_H

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../utils/general.h"

typedef enum key_size {
    SIZE_128 = 16,
    SIZE_192 = 24,
    SIZE_256 = 32
} aes_key_size;

uint8_t aes(uint8_t* plaintext, uint8_t* ciphertext, uint8_t* key, aes_key_size size, bool decrypt);

#endif