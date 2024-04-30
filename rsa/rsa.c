#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "rsa.h"
#include "../sha256/sha256.h"
#include "../utils/general.h"

static void rsa_generate_decryption_key(const mpz_t p, const mpz_t q, const mpz_t enc_key, mpz_t n, mpz_t dec_key) {
    // Multiply two big primes (p & q) to obtain the modulo (n);
    mpz_mul(n, p, q);

    mpz_t temp, p_temp, q_temp, lambda, gcd, product;
    // Initialize mpz_t variables to 0;
    mpz_inits(temp, p_temp, q_temp, lambda, gcd, product, NULL);

    // Compute the Carmichael totient - lambda(n);
    // Since n = pq => lambda(n) = lcm(lambda(p), lambda(q));
    // If x is prime => lambda(x) = phi(x) = x - 1 => lambda(n) = lcm(p - 1, q - 1);
    mpz_sub_ui(p_temp, p, 1);
    mpz_sub_ui(q_temp, q, 1);
    mpz_lcm(lambda, p_temp, q_temp);

    // The encryption key is co-prime to lambda and 3 < enc < lambda(n);
    assert(mpz_cmp_ui(enc_key, 3) > 0);
    assert(mpz_cmp(lambda, enc_key));
    mpz_gcd(gcd, enc_key, lambda);
    assert(mpz_cmp_ui(gcd, 1) == 0);

    // The decryption key is the modular inverse of the encryption key modulo lambda(n);
    // That means (e * d) % lambda(n) = 1,  d - rop, e - op1, lambda(n) - op2;
    mpz_invert(dec_key, enc_key, lambda);
    // Check if (e * d) % lambda(n) = 1;
    mpz_mul(product, dec_key, enc_key);
    mpz_mod(temp, product, lambda);
    assert(mpz_cmp_ui(temp, 1) == 0);

    mpz_clears(temp, p_temp, q_temp, lambda, gcd, product, NULL);
}

static void rsa_encrypt(const mpz_t plain, const mpz_t enc_key, const mpz_t n, mpz_t cipher) {
    // Let m represent the plaintext => the ciphertext is c = m^e mod(n);
    mpz_powm(cipher, plain, enc_key, n);
}

static void rsa_decrypt(const mpz_t cipher, const mpz_t dec_key, const mpz_t n, mpz_t plain) {
    // Let c represent the ciphertext => the plaintext is m = c^d mod(n);
    mpz_powm(plain, cipher, dec_key, n);
}

void rsa(const uint8_t* data_string, const size_t data_len, const char* p_string, const char* q_string, const char* enc_key_string) {
    mpz_t data, p, q, n, enc_key, dec_key, plain, cipher;
    mpz_inits(n, dec_key, plain, cipher, NULL);
    // The data passed to RSA will be a hex byte array => use base 16 to convert it to a integer;
    // mpz_init_set_str(data, data_string, 16);
    mpz_import(data, data_len, 1, 1, 0, 0, data_string);
    mpz_init_set_str(p, p_string, 10);
    mpz_init_set_str(q, q_string, 10);
    mpz_init_set_str(enc_key, enc_key_string, 10);

    // Generate the decryption key;
    rsa_generate_decryption_key(p, q, enc_key, n, dec_key);

    // Encrypt the data;
    rsa_encrypt(data, enc_key, n, cipher);
    // Decrypt the data;
    rsa_decrypt(cipher, dec_key, n, plain);

    printf("Public = (e: %s, n: %s)\n", mpz_get_str(NULL, 0, enc_key), mpz_get_str(NULL, 0, n));
    printf("Private = (d: %s, n: %s)\n", mpz_get_str(NULL, 0, dec_key), mpz_get_str(NULL, 0, n));
    printf("Original message: %s\n", mpz_get_str(NULL, 0, data));
    printf("Encrypted message: %s\n", mpz_get_str(NULL, 0, cipher));
    printf("Decrypted message: %s\n", mpz_get_str(NULL, 0, plain));
    printf("\n");
}

// void rsa_oaep(const uint8_t* message, const size_t message_len, const uint8_t* parameter, const size_t param_len, uint8_t** em, const size_t em_len) {
//     // Assume a modulo n with length nLen = 1024 bits = 128 bytes;
//     // As such, the message representative em will have a max length of emMaxLen = 128 bytes;
//     // Assume usage of SHA2-256 as the hash function => hLen = 256 bits = 32 bytes;
//     // The minimum length of em, emMinLen = 2 * hLen + 1;
//     // Therefore, the maximum length of the message m is mMaxLen = emMaxLen - 1 - 2 * hLen;
//     // Inputs :
//     //  - M     - the message to be padded;
//     //          - if mLen > eMaxLen - 1 - 2 * hLen return error;
//     //  - P     - the parameter string;
//     //          - if P is too large for SHA2-256 ie. pLen > 2^64 - 1 bits long return error;
//     //  - emLen - intented length of em in bytes;
//     // Outputs :
//     //  - EM    - the resulting message representative of length emLen;
//     // Steps :
//     //  - Generate a byte array PS of 0x00 and length psLen = emLen - mLen - 2 * hLen - 1 (can be 0);
//     size_t ps_len = em_len - message_len - 2 * SHA256_DIGEST_SIZE - 1;
//     //  - Let pHash = SHA2-256(P) a byte array of length hLen;
//     uint8_t* p_hash = NULL;
//     sha256(parameter, param_len, &p_hash);
//     //  - Concatenate pHash, PS, M and other padding to form a data block DB = pHash || PS || 01 || M;
//     //  - dbLen = hLen + psLen + 1 + mLen;
//     size_t data_block_len = SHA256_DIGEST_SIZE + ps_len + 1 + message_len;
//     uint8_t* data_block = safe_malloc(data_block_len * sizeof *data_block);
//     // DB = pHash;
//     memcpy(data_block, p_hash, SHA256_DIGEST_SIZE);
//     // DB = pHash || PS;
//     memset(data_block + SHA256_DIGEST_SIZE, 0, ps_len);
//     // DB = pHash || PS || 01;
//     memset(data_block + SHA256_DIGEST_SIZE + ps_len, 0x80, 1);
//     // DB = pHash || PS || 01 || M;
//     memcpy(data_block + SHA256_DIGEST_SIZE + ps_len + 1, message, message_len);
//     //  - Generate a random byte array seed of length hLen;
// }

// void rsa_generate_mask(const uint8_t* seed, const size_t seed_len, uint8_t* mask, uint32_t mask_len) {
//     uint32_t counter = 0;
//     uint32_t current_mask_len = 0;
//     uint8_t bytes[4];
//     uint8_t* temp = safe_malloc((seed_len + 4) * sizeof *temp);
//     uint8_t* digest = NULL;

//     while (current_mask_len < mask_len) {
//         // Convert the counter to a byte array of length 4;
//         bytes[0] = (counter >> 24) & 0xFF;
//         bytes[1] = (counter >> 16) & 0xFF;
//         bytes[2] = (counter >> 8) & 0xFF;
//         bytes[3] = counter & 0xFF;
//         // Concatenate the seed and the counter byte array and hash the result;
//         memcpy(temp, seed, seed_len);
//         memcpy(temp + seed_len, bytes, 4);
//         sha256(temp, seed_len + 4, &digest);
//     }
// }