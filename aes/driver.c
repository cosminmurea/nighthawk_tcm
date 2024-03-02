#include <string.h>
#include "aes.h"
#include "../utils/general.h"
#include "../utils/pkcs7.h"
#include "../chaos/entropy.h"

int main() {
    // uint8_t key[16] = {
    //     0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    // };
    // uint8_t input[16] = {
    //     0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    // };
    // uint8_t iv[16] = {
    //     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    // };

    uint8_t* key = hex_to_byte_array("2b7e151628aed2a6abf7158809cf4f3", 31);
    print_byte_array(key, 16);

    /**
     * --------------------------------------------------------------------------------------------------
     * Testing the entropy generation functionalities.
     * --------------------------------------------------------------------------------------------------
    */

    // // Sourcing entropy from /dev/urandom
    // uint8_t key2[32] = { 0 };
    // bm_generate_entropy(key2, 32);
    // print_bytes_hex(key2, 32);

    /**
     * --------------------------------------------------------------------------------------------------
     * Testing the PKCS7 padding functionalities.
     * --------------------------------------------------------------------------------------------------
    */

    // // Padding
    // uint8_t* padded = NULL;
    // size_t padded_length = 0;
    // pkcs7_pad(input, 16, &padded, &padded_length);
    // print_bytes_hex(padded, padded_length);

    // // Unpadding
    // uint8_t* data = NULL;
    // size_t data_length = 0;
    // pkcs7_unpad(padded, padded_length, &data, &data_length);
    // print_bytes_hex(data, data_length);

    // free(padded);
    // free(data);

    /**
     * --------------------------------------------------------------------------------------------------
     * Testing the AES CBC functionalities.
     * --------------------------------------------------------------------------------------------------
    */

    //// Encryption
    // aes_cbc_ctx* enc_ctx = aes_cbc_encrypt(input, 16, iv, key, AES_KEY_SIZE_128);
    // print_bytes_hex(input, 16);
    // size_t cipher_length = aes_cbc_get_cipher_length(enc_ctx);
    // uint8_t temp[cipher_length];
    // memcpy(temp, aes_cbc_get_cipher(enc_ctx), cipher_length);
    // aes_cbc_destroy(enc_ctx);
    // print_bytes_hex(temp, cipher_length);

    //// Decryption
    // aes_cbc_ctx* dec_ctx = aes_cbc_decrypt(temp, cipher_length, iv, key, AES_KEY_SIZE_128);
    // size_t plain_length = aes_cbc_get_plain_length(dec_ctx);
    // uint8_t temp2[plain_length];
    // memcpy(temp2, aes_cbc_get_plain(dec_ctx), plain_length);
    // aes_cbc_destroy(dec_ctx);
    // print_bytes_hex(temp2, plain_length);

    return 0;
}