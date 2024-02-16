#include <stdio.h>
#include "aes.h"

int main() {
    size_t expanded_key_size = 240;
    uint8_t expanded_key[expanded_key_size];
    uint8_t key[32] = { 0 };
    uint8_t state[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    uint8_t column[4] = { 0xDB, 0x13, 0x53, 0x45 };
    aes_key_size size = SIZE_256;
    key_expansion(expanded_key, key, size, expanded_key_size);

    printf("The expanded key is : \n");
    for (size_t i = 0; i < expanded_key_size; i++) {
        printf("%2.2X%c", expanded_key[i], ((i + 1) % 16 == 0) ? '\n' : ' ');
    }
    printf("\n");

    mix_column(column);
    for (size_t i = 0; i < 4; i++) {
        printf("%2.2X%c", column[i], ((i + 1) % 4 == 0) ? '\n' : ' ');
    }

    return 0;
}