#include "aes.h"
#include "../utils/general.h"
#include "../utils/pkcs7.h"

int main() {
    uint8_t key[24] = {
        0xBA, 0x75, 0xF4, 0xD1, 0xD9, 0xD7, 0xCF, 0x7F, 0x55, 0x14, 0x45, 0xD5, 0x6C, 0xC1, 0xA8, 0xAB,
        0x2A, 0x07, 0x8E, 0x15, 0xE0, 0x49, 0xDC, 0x2C
    };
    uint8_t input[16] = {
        0xc5, 0x1f, 0xc2, 0x76, 0x77, 0x4d, 0xad, 0x94, 0xbc, 0xdc, 0x1d, 0x28, 0x91, 0xec, 0x86, 0x68
    };
    uint8_t iv[16] = {
        0x53, 0x1c, 0xe7, 0x81, 0x76, 0x40, 0x16, 0x66, 0xaa, 0x30, 0xdb, 0x94, 0xec, 0x4a, 0x30, 0xeb
    };

    // uint8_t* cipher = NULL;
    // uint8_t* plain = NULL;
    // size_t plain_len = 0;
    // size_t cipher_len = 0;
    // aes_cbc_encrypt(input, 16, iv, key, 24, &cipher, &cipher_len);
    // print_byte_array(cipher, 32);
    // aes_cbc_decrypt(cipher, 32, iv, key, 24, &plain, &plain_len);
    // print_byte_array(plain, plain_len);
    // free(plain);
    // free(cipher);

    aes_cbc_test("./test_vectors/AESCBC128LongMsg.rsp", AES_KEY_SIZE_128);
    aes_cbc_test("./test_vectors/AESCBC192LongMsg.rsp", AES_KEY_SIZE_192);
    aes_cbc_test("./test_vectors/AESCBC256LongMsg.rsp", AES_KEY_SIZE_256);

    return 0;
}