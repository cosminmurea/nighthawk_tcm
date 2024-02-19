#include "aes.h"
#include "../utils/pkcs7.h"

int main() {
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    uint8_t input[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    uint8_t output[16], output2[16];
    aes_key_size size = SIZE_128;
    // aes(input, output, key, size, false);
    // print_bytes_hex(output, 16);
    // aes(output, output2, key, size, true);
    // print_bytes_hex(output2, 16);
    pkcs7_context* pkcs7_context = pkcs7_context_init(input, 16, 16);
    pkcs7_pad(pkcs7_context);
    print_bytes_hex(pkcs7_context->padded_data, pkcs7_context->padded_data_length);
    pkcs7_context = pkcs7_unpad(pkcs7_context->padded_data, pkcs7_context->padded_data_length, pkcs7_context->block_size);
    print_bytes_hex(pkcs7_context->data, pkcs7_context->data_length);
    pkcs7_context_destroy(pkcs7_context);
    return 0;
}