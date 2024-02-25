#include <string.h>
#include "aes.h"
#include "../utils/general.h"
#include "../utils/pkcs7.h"

int main() {
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    uint8_t input[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    uint8_t iv[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    // print_bytes_hex(input, 6);
    // pkcs7_pad_ctx* pad_ctx = pkcs7_pad(input, 6, AES_BLOCK_SIZE);
    // print_bytes_hex(pkcs7_get_padded(pad_ctx), pkcs7_get_padded_length(pad_ctx));
    // pkcs7_unpad_ctx* unpad_ctx = pkcs7_unpad(pkcs7_get_padded(pad_ctx), pkcs7_get_padded_length(pad_ctx));
    // print_bytes_hex(pkcs7_get_unpadded(unpad_ctx), pkcs7_get_unpadded_length(unpad_ctx));
    // pkcs7_destroy_pad_ctx(pad_ctx);
    // pkcs7_destroy_unpad_ctx(unpad_ctx);
    uint8_t* ciphertext = aes_cbc_encrypt(input, 16, iv, key, AES_KEY_SIZE_128);
    print_bytes_hex(ciphertext, 32);
    print_bytes_hex(input, 16);
    uint8_t* plaintext = aes_cbc_decrypt(ciphertext, 32, iv, key, AES_KEY_SIZE_128);
    print_bytes_hex(plaintext, 16);
    print_bytes_hex(input, 16);
    // pkcs7_pad_ctx* pad_ctx = pkcs7_pad(input, 16, 32);
    // print_bytes_hex(pkcs7_get_padded(pad_ctx), pkcs7_get_padded_length(pad_ctx));
    // pkcs7_unpad_ctx* unpad_ctx = pkcs7_unpad(pad_ctx, 32);
    // print_bytes_hex(pkcs7_get_unpadded(unpad_ctx), pkcs7_get_unpadded_length(unpad_ctx));
    return 0;
}