#include <stdio.h>
#include "aes.h"

int main() {
    size_t expanded_key_size = 240;
    uint8_t expanded_key[expanded_key_size];
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    uint8_t input[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    uint8_t output[16];
    aes_key_size size = SIZE_128;
    aes_encrypt(input, output, key, size);

    for (size_t i = 0; i < 16; i++) {
        printf("%2.2X%c", output[i], ((i + 1) % 4 == 0) ? '\n' : ' ');
    }
    // key_expansion(expanded_key, key, size, expanded_key_size);

    // printf("The expanded key is : \n");
    // for (size_t i = 0; i < expanded_key_size; i++) {
    //     printf("%2.2X%c", expanded_key[i], ((i + 1) % 16 == 0) ? '\n' : ' ');
    // }
    // printf("\n");

    // mix_column(column);
    // for (size_t i = 0; i < 4; i++) {
    //     printf("%2.2X%c", column[i], ((i + 1) % 4 == 0) ? '\n' : ' ');
    // }

    return 0;
}