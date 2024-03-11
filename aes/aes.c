#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "aes.h"
#include "../utils/general.h"
#include "../utils/pkcs7.h"

#define AES_MAX_TEST_MSG_LENGTH 350

static const uint8_t s_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t inverse_s_box[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t rcon[255] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
};

static void row_col_map(uint8_t* dest, uint8_t* src) {
    for (uint8_t i = 0; i < AES_WORD_SIZE; i++) {
        for (uint8_t j = 0; j < AES_WORD_SIZE; j++) {
            dest[i + AES_WORD_SIZE * j] = src[i * AES_WORD_SIZE + j];
        }
    }
}

static uint8_t get_s_box_value(uint8_t index) {
    return s_box[index];
}

static uint8_t get_s_box_inverse(uint8_t index) {
    return inverse_s_box[index];
}

static uint8_t get_rcon_value(uint8_t iteration) {
    return rcon[iteration];
}

static void rotate_word(uint8_t* word) {
    uint8_t byte;
    byte = word[0];
    for (uint8_t i = 0; i < AES_WORD_SIZE - 1; i++) {
        word[i] = word[i + 1];
    }
    word[AES_WORD_SIZE - 1] = byte;
}

static void key_schedule(uint8_t* word, size_t iteration) {
    rotate_word(word);
    for (uint8_t i = 0; i < AES_WORD_SIZE; i++) {
        word[i] = get_s_box_value(word[i]);
    }
    word[0] ^= get_rcon_value(iteration);
}

static void key_expansion(uint8_t* key, uint8_t key_size, uint8_t* expanded_key, size_t expanded_key_size) {
    size_t current_size = 0;
    size_t rcon_iteration = 1;
    uint8_t temp_word[AES_WORD_SIZE] = { 0 };
    for (uint8_t i = 0; i < key_size; i++) {
        expanded_key[i] = key[i];
    }
    current_size += key_size;
    while (current_size < expanded_key_size) {
        for (uint8_t i = 0; i < AES_WORD_SIZE; i++) {
            temp_word[i] = expanded_key[(current_size - AES_WORD_SIZE) + i];
        }
        if (current_size % key_size == 0) {
            key_schedule(temp_word, rcon_iteration);
            rcon_iteration++;
        }
        if ((key_size == AES_KEY_SIZE_256) && (current_size % key_size == AES_BLOCK_SIZE)) {
            for (uint8_t i = 0; i < AES_WORD_SIZE; i++) {
                temp_word[i] = get_s_box_value(temp_word[i]);
            }
        }
        for (uint8_t i = 0; i < AES_WORD_SIZE; i++) {
            expanded_key[current_size] = expanded_key[current_size - key_size] ^ temp_word[i];
            current_size++;
        }
    }
}

static void sub_bytes(uint8_t* state, bool decrypt) {
    for (uint8_t i = 0; i < AES_BLOCK_SIZE; i++) {
        if (decrypt) {
            state[i] = get_s_box_inverse(state[i]);
        } else {
            state[i] = get_s_box_value(state[i]);
        }
    }
}

static void shift_rows(uint8_t* state, bool decrypt) {
    uint8_t temp[AES_WORD_SIZE] = { 0 };
    for (uint8_t i = 1; i < AES_WORD_SIZE; i++) {
        if (decrypt) {
            memcpy(temp + i, state + i * AES_WORD_SIZE, AES_WORD_SIZE - i);
            memcpy(temp, state + AES_WORD_SIZE + (i * (AES_WORD_SIZE - 1)), i);
            memcpy(state + i * AES_WORD_SIZE, temp, AES_WORD_SIZE);
        } else {
            memcpy(temp, (state + i * (AES_WORD_SIZE + 1)), AES_WORD_SIZE - i);
            memcpy((temp + AES_WORD_SIZE - i), (state + i * AES_WORD_SIZE), i);
            memcpy(state + i * AES_WORD_SIZE, temp, AES_WORD_SIZE);
        }
    }
}

static void add_round_key(uint8_t* state, uint8_t* round_key) {
    for (uint8_t i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] ^= round_key[i];
    }
}

static uint8_t g_mult(uint8_t poly_A, uint8_t poly_B) {
    uint8_t product = 0;
    uint8_t high_bit = 0;
    for (uint8_t i = 0; i < 8; i++) {
        if ((poly_B & 1) == 1) {
            product ^= poly_A;
        }
        high_bit = (poly_A & 0x80);
        poly_A <<= 1;
        if (high_bit == 0x80) {
            poly_A ^= 0x1B;
        }
        poly_B >>= 1;
    }
    return product;
}

static void mix_column(uint8_t* column, bool decrypt) {
    uint8_t temp[AES_WORD_SIZE];
    memcpy(temp, column, AES_WORD_SIZE);
    if (decrypt) {
        column[0] = g_mult(temp[0], 14) ^ g_mult(temp[3], 9) ^ g_mult(temp[2], 13) ^ g_mult(temp[1], 11);
        column[1] = g_mult(temp[1], 14) ^ g_mult(temp[0], 9) ^ g_mult(temp[3], 13) ^ g_mult(temp[2], 11);
        column[2] = g_mult(temp[2], 14) ^ g_mult(temp[1], 9) ^ g_mult(temp[0], 13) ^ g_mult(temp[3], 11);
        column[3] = g_mult(temp[3], 14) ^ g_mult(temp[2], 9) ^ g_mult(temp[1], 13) ^ g_mult(temp[0], 11);
    } else {
        column[0] = g_mult(temp[0], 2) ^ g_mult(temp[3], 1) ^ g_mult(temp[2], 1) ^ g_mult(temp[1], 3);
        column[1] = g_mult(temp[1], 2) ^ g_mult(temp[0], 1) ^ g_mult(temp[3], 1) ^ g_mult(temp[2], 3);
        column[2] = g_mult(temp[2], 2) ^ g_mult(temp[1], 1) ^ g_mult(temp[0], 1) ^ g_mult(temp[3], 3);
        column[3] = g_mult(temp[3], 2) ^ g_mult(temp[2], 1) ^ g_mult(temp[1], 1) ^ g_mult(temp[0], 3);
    }
}

static void mix_columns(uint8_t* state, bool decrypt) {
    uint8_t column[AES_WORD_SIZE];
    for (uint8_t i = 0; i < AES_WORD_SIZE; i++) {
        for (uint8_t j = 0; j < AES_WORD_SIZE; j++) {
            column[j] = state[j * AES_WORD_SIZE + i];
        }
        mix_column(column, decrypt);
        for (uint8_t j = 0; j < AES_WORD_SIZE; j++) {
            state[j * AES_WORD_SIZE + i] = column[j];
        }
    }
}

static void aes_round(uint8_t* state, uint8_t* round_key, bool decrypt) {
    if (decrypt) {
        shift_rows(state, true);
        sub_bytes(state, true);
        add_round_key(state, round_key);
        mix_columns(state, true);
    } else {
        sub_bytes(state, false);
        shift_rows(state, false);
        mix_columns(state, false);
        add_round_key(state, round_key);
    }
}

static void generate_round_key(uint8_t* expanded_key, uint8_t* round_key) {
    row_col_map(round_key, expanded_key);
}

static void aes_main(uint8_t* state, uint8_t* expanded_key, uint8_t nr_rounds, bool decrypt) {
    uint8_t round_key[AES_BLOCK_SIZE] = { 0 };
    if (decrypt) {
        generate_round_key(expanded_key + AES_BLOCK_SIZE * nr_rounds, round_key);
        add_round_key(state, round_key);
        for (uint8_t i = nr_rounds - 1; i > 0; i--) {
            generate_round_key(expanded_key + AES_BLOCK_SIZE * i, round_key);
            aes_round(state, round_key, true);
        }
        generate_round_key(expanded_key, round_key);
        shift_rows(state, true);
        sub_bytes(state, true);
        add_round_key(state, round_key);
    } else {
        generate_round_key(expanded_key, round_key);
        add_round_key(state, round_key);
        for (uint8_t i = 1; i < nr_rounds; i++) {
            generate_round_key(expanded_key + AES_BLOCK_SIZE * i, round_key);
            aes_round(state, round_key, false);
        }
        generate_round_key(expanded_key + AES_BLOCK_SIZE * nr_rounds, round_key);
        sub_bytes(state, false);
        shift_rows(state, false);
        add_round_key(state, round_key);
    }
}

uint8_t aes(uint8_t* data_block, uint8_t* cipher_block, uint8_t* key, uint8_t key_size, bool decrypt) {
    size_t expanded_key_size = 0;
    uint8_t nr_rounds = 0;
    uint8_t* expanded_key = NULL;
    uint8_t block[AES_BLOCK_SIZE] = { 0 };
    switch (key_size) {
        case AES_KEY_SIZE_128:
            nr_rounds = 10;
            break;
        case AES_KEY_SIZE_192:
            nr_rounds = 12;
            break;
        case AES_KEY_SIZE_256:
            nr_rounds = 14;
            break;
        default:
            return -1;
            break;
    }
    expanded_key_size = AES_BLOCK_SIZE * (nr_rounds + 1);
    expanded_key = safe_malloc(expanded_key_size * sizeof *expanded_key);
    row_col_map(block, data_block);
    key_expansion(key, key_size, expanded_key, expanded_key_size);
    aes_main(block, expanded_key, nr_rounds, decrypt);
    row_col_map(cipher_block, block);
    free(expanded_key);
    return 0;
}

void aes_cbc_encrypt(const uint8_t* plain, size_t plain_len, uint8_t* iv, uint8_t* key, uint8_t key_size, uint8_t** cipher, size_t* cipher_len) {
    uint8_t* padded = NULL;
    uint8_t temp_iv[AES_BLOCK_SIZE];
    memcpy(temp_iv, iv, AES_BLOCK_SIZE);
    // Pad the plaintext and store it in the padded buffer;
    pkcs7_pad(plain, plain_len, &padded, cipher_len);
    *cipher = safe_malloc(*cipher_len * sizeof **cipher);
    // For each block of the plaintext XOR it with the IV and then encrypt;
    for (size_t i = 0; i < *cipher_len; i += AES_BLOCK_SIZE) {
        for (uint8_t j = 0; j < AES_BLOCK_SIZE; j++) {
            padded[i + j] ^= temp_iv[j];
        }
        aes(padded + i, *cipher + i, key, key_size, false);
        // The next IV is the current encrypted block;
        memcpy(temp_iv, *cipher + i, AES_BLOCK_SIZE);
    }
    free(padded);
}

void aes_cbc_decrypt(const uint8_t* cipher, size_t cipher_len, uint8_t* iv, uint8_t* key, uint8_t key_size, uint8_t** plain, size_t* plain_len) {
    uint8_t* padded = safe_malloc(cipher_len * sizeof *padded);
    memcpy(padded, cipher, cipher_len);
    uint8_t temp_iv[AES_BLOCK_SIZE], temp_iv2[AES_BLOCK_SIZE];
    memcpy(temp_iv, iv, AES_BLOCK_SIZE);
    // For each block of the ciphertext decrypt it and the XOR it with the IV;
    for (size_t i = 0; i < cipher_len; i += AES_BLOCK_SIZE) {
        // Save the current cipher block to use as the next IV;
        memcpy(temp_iv2, padded + i, AES_BLOCK_SIZE);
        aes(padded + i, padded + i, key, key_size, true);
        for (uint8_t j = 0; j < AES_BLOCK_SIZE; j++) {
            padded[i + j] ^= temp_iv[j];
        }
        memcpy(temp_iv, temp_iv2, AES_BLOCK_SIZE);

    }
    pkcs7_unpad(padded, cipher_len, plain, plain_len);
    free(padded);
}

static void aes_cbc_decrypt_no_pad(const uint8_t* cipher, size_t cipher_len, uint8_t* iv, uint8_t* key, uint8_t key_size, uint8_t** plain, size_t* plain_len) {
    uint8_t* padded = safe_malloc(cipher_len * sizeof *padded);
    memcpy(padded, cipher, cipher_len);
    uint8_t temp_iv[AES_BLOCK_SIZE], temp_iv2[AES_BLOCK_SIZE];
    memcpy(temp_iv, iv, AES_BLOCK_SIZE);
    // For each block of the ciphertext decrypt it and the XOR it with the IV;
    for (size_t i = 0; i < cipher_len; i += AES_BLOCK_SIZE) {
        // Save the current cipher block to use as the next IV;
        memcpy(temp_iv2, padded + i, AES_BLOCK_SIZE);
        aes(padded + i, padded + i, key, key_size, true);
        for (uint8_t j = 0; j < AES_BLOCK_SIZE; j++) {
            padded[i + j] ^= temp_iv[j];
        }
        memcpy(temp_iv, temp_iv2, AES_BLOCK_SIZE);

    }
    // pkcs7_unpad(cipher, cipher_len, plain, plain_len);
    *plain_len = cipher_len;
    *plain = safe_malloc(*plain_len * sizeof **plain);
    memcpy(*plain, padded, cipher_len);
    free(padded);
}

void aes_cbc_test(const char* test_file, uint8_t key_size) {
    // Open the test file;
    FILE* file_ptr = safe_fopen(test_file, "rb");
    char buffer[AES_MAX_TEST_MSG_LENGTH];
    uint8_t* key = NULL;
    uint8_t* iv = NULL;
    uint8_t* plain = NULL;
    size_t plain_len = 0;
    uint8_t* cipher = NULL;
    uint8_t* nist_cipher = NULL;
    size_t cipher_len = 0;
    size_t count = 1;

    while (fgets(buffer, AES_MAX_TEST_MSG_LENGTH, file_ptr)) {
        // Read the key and convert it to a byte array;
        sscanf(buffer, "KEY = %s", buffer);
        key = hex_to_byte_array(buffer, key_size * 2);
        printf("KEY = \t\t");
        print_byte_array(key, key_size);
        memset(buffer, 0, AES_MAX_TEST_MSG_LENGTH);
        // Read the IV and convert it to a byte array;
        fgets(buffer, AES_MAX_TEST_MSG_LENGTH, file_ptr);
        sscanf(buffer, "IV = %s", buffer);
        iv = hex_to_byte_array(buffer, AES_BLOCK_SIZE * 2);
        printf("IV = \t\t");
        print_byte_array(iv, AES_BLOCK_SIZE);
        memset(buffer, 0, AES_MAX_TEST_MSG_LENGTH);
        if (count > 10) {
            plain_len = (count - 10) * AES_BLOCK_SIZE;
            // Read the ciphertext and convert it to a byte array;
            fgets(buffer, AES_MAX_TEST_MSG_LENGTH, file_ptr);
            sscanf(buffer, "CIPHERTEXT = %s", buffer);
            nist_cipher = hex_to_byte_array(buffer, plain_len * 2);
            printf("CIPHER = \t");
            print_byte_array(nist_cipher, plain_len);
            memset(buffer, 0, AES_MAX_TEST_MSG_LENGTH);
            // Read the plaintext and convert it to a byte array;
            fgets(buffer, AES_MAX_TEST_MSG_LENGTH, file_ptr);
            sscanf(buffer, "PLAINTEXT = %s", buffer);
            plain = hex_to_byte_array(buffer, plain_len * 2);
            printf("PLAIN = \t");
            print_byte_array(plain, plain_len);
            memset(buffer, 0, AES_MAX_TEST_MSG_LENGTH);
            // Apply decryption;
            aes_cbc_decrypt_no_pad(nist_cipher, plain_len, iv, key, key_size, &cipher, &cipher_len);
            printf("LOCAL = \t");
            print_byte_array(cipher, cipher_len);
        } else {
            plain_len = count * AES_BLOCK_SIZE;
            // Read the plaintext and convert it to a byte array;
            fgets(buffer, AES_MAX_TEST_MSG_LENGTH, file_ptr);
            sscanf(buffer, "PLAINTEXT = %s", buffer);
            plain = hex_to_byte_array(buffer, plain_len * 2);
            printf("PLAIN = \t");
            print_byte_array(plain, plain_len);
            memset(buffer, 0, AES_MAX_TEST_MSG_LENGTH);
            // Read the ciphertext and convert it to a byte array;
            fgets(buffer, AES_MAX_TEST_MSG_LENGTH, file_ptr);
            sscanf(buffer, "CIPHERTEXT = %s", buffer);
            nist_cipher = hex_to_byte_array(buffer, plain_len * 2);
            printf("CIPHER = \t");
            print_byte_array(nist_cipher, plain_len);
            memset(buffer, 0, AES_MAX_TEST_MSG_LENGTH);
            // Apply decryption;
            aes_cbc_encrypt(plain, plain_len, iv, key, key_size, &cipher, &cipher_len);
            printf("LOCAL = \t");
            print_byte_array(cipher, cipher_len - 16);
        }
        // Every fifth line is empty;
        fgets(buffer, AES_MAX_TEST_MSG_LENGTH, file_ptr);
        memset(buffer, 0, AES_MAX_TEST_MSG_LENGTH);
        printf("\n");
        count++;
    }
    fclose(file_ptr);
    free(key);
    free(iv);
    free(nist_cipher);
    free(plain);
    free(cipher);
}