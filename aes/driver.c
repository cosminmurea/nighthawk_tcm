#include "aes.h"
#include "../utils/general.h"
#include "../utils/pkcs7.h"

int main() {
    uint8_t key[16] = {
        0xac, 0x58, 0x00, 0xac, 0x3c, 0xb5, 0x9c, 0x7c, 0x14, 0xf3, 0x60, 0x19, 0xe4, 0x3b, 0x44, 0xfe
    };
    uint8_t input[6] = {
        0xf6, 0xce, 0xe5, 0xff, 0x28, 0xfd
    };
    uint8_t iv[16] = {
        0xf0, 0x13, 0xce, 0x1e, 0xc9, 0x01, 0xb5, 0xb6, 0x0a, 0x85, 0xa9, 0x86, 0xb3, 0xb7, 0x2e, 0xba
    };
    print_bytes_hex(input, 6);
    pkcs7_pad_ctx* pad_ctx = pkcs7_pad(input, 6, AES_BLOCK_SIZE);
    print_bytes_hex(pkcs7_get_padded(pad_ctx), pkcs7_get_padded_length(pad_ctx));
    pkcs7_unpad_ctx* unpad_ctx = pkcs7_unpad(pkcs7_get_padded(pad_ctx), pkcs7_get_padded_length(pad_ctx));
    print_bytes_hex(pkcs7_get_unpadded(unpad_ctx), pkcs7_get_unpadded_length(unpad_ctx));
    pkcs7_destroy_pad_ctx(pad_ctx);
    pkcs7_destroy_unpad_ctx(unpad_ctx);
    // uint8_t* cipher = aes_cbc_encrypt(input, iv, 6, key, AES_KEY_SIZE_128);
    // print_bytes_hex(cipher, 16);
    // print_bytes_hex(input, 16);
    // pkcs7_pad_ctx* pad_ctx = pkcs7_pad(input, 16, 32);
    // print_bytes_hex(pkcs7_get_padded(pad_ctx), pkcs7_get_padded_length(pad_ctx));
    // pkcs7_unpad_ctx* unpad_ctx = pkcs7_unpad(pad_ctx, 32);
    // print_bytes_hex(pkcs7_get_unpadded(unpad_ctx), pkcs7_get_unpadded_length(unpad_ctx));
    return 0;
}