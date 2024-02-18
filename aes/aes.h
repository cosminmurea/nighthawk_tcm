#ifndef AES_H
#define AES_H

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

typedef enum key_size {
    SIZE_128 = 16,
    SIZE_192 = 24,
    SIZE_256 = 32
} aes_key_size;

void print_hex(uint8_t* byte_array, size_t length);

uint8_t get_s_box_value(uint8_t index);
uint8_t get_s_box_inverse(uint8_t index);
uint8_t get_rcon_value(uint8_t iteration);

void rotate_word(uint8_t* word);
void key_schedule(uint8_t* word, size_t iteration);
void key_expansion(uint8_t* expanded_key, uint8_t* key, aes_key_size size, size_t expanded_key_size);

void sub_bytes(uint8_t* state, bool decrypt);
void shift_rows(uint8_t* state, bool decrypt);
void add_round_key(uint8_t* state, uint8_t* round_key);
uint8_t g_mult(uint8_t poly_A, uint8_t poly_B);
void mix_column(uint8_t* column, bool decrypt);
void mix_columns(uint8_t* state, bool decrypt);

void aes_round(uint8_t* state, uint8_t* round_key, bool decrypt);
void generate_round_key(uint8_t* expanded_key, uint8_t* round_key);
void aes_main(uint8_t* state, uint8_t* expanded_key, size_t nr_rounds, bool decrypt);
uint8_t aes(uint8_t* plaintext, uint8_t* ciphertext, uint8_t* key, aes_key_size size, bool decrypt);

#endif