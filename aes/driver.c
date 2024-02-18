#include <stdio.h>
#include "aes.h"

void print_hex(uint8_t* array, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%2.2x", array[i]);
    }
    printf("\n");
}

int main() {
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    uint8_t input[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    uint8_t output[16], output2[16];
    aes_key_size size = SIZE_128;
    aes(input, output, key, size, false);
    print_hex(output, 16);
    aes(output, output2, key, size, true);
    print_hex(output2, 16);
    print_hex(input, 16);
    return 0;
}