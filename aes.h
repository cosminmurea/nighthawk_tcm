#ifndef AES_H
#define AES_H

#include <stdlib.h>
#include <string.h>

typedef enum key_size {
    SIZE_128 = 16,
    SIZE_192 = 24,
    SIZE_256 = 32
} aes_key_size;

uint8_t get_s_box_value(uint8_t index);
uint8_t get_s_box_inverse(uint8_t index);
uint8_t get_rcon_value(uint8_t iteration);

void rotate(uint8_t* word);
void key_schedule(uint8_t* word, size_t iteration);
void key_expansion(uint8_t* expanded_key, uint8_t* key, aes_key_size size, size_t expanded_key_size);

void sub_bytes(uint8_t* state);
void shift_rows(uint8_t* state);
void add_round_key(uint8_t* state, uint8_t* round_key);
uint8_t g_multiply(uint8_t poly_A, uint8_t poly_B);
void mix_column(uint8_t* column);
void mix_columns(uint8_t* state);
void round(uint8_t* state, uint8_t* round_key);
void generate_round_key(uint8_t* expanded_key, uint8_t* round_key);
void aes_main(uint8_t* state, uint8_t* expanded_key, size_t nr_rounds);
uint8_t aes_encrypt(uint8_t* plaintext, uint8_t* ciphertext, uint8_t* key, aes_key_size size);

#endif