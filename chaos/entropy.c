#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include "entropy.h"

// The length of the internal seed for the bifurcation map in bytes.
// The initial population value is a double => the seed is 8 bytes long.
#define INTERNAL_SEED_LEN 8
// The number of iterations for the bifurcation map to reach a chaotic state.
#define BM_WARMUP_ITER 10000

// Generates a 64-bit seed as a byte array (8 * 8) using /dev/urandom.
static void urandom(uint8_t* seed) {
    // Open /dev/urandom and save the file descriptor;
    int32_t urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd == -1) {
        fprintf(stderr, "Could not open /dev/urandom. Proceeding to crash. Cleaning up...");
        exit(EXIT_FAILURE);
    }
    // Read from /dev/urandom and store into the seed buffer;
    if (read(urandom_fd, seed, INTERNAL_SEED_LEN) != INTERNAL_SEED_LEN) {
        fprintf(stderr, "Could not read from /dev/urandom. Proceeding to crash. Cleaning up...");
        exit(EXIT_FAILURE);
    }
    close(urandom_fd);
}

// Implements the bifuraction map x(n + 1) = r * x(n) * (1 - x(n)).
static double bifurcation_map(double x, double r) {
    return r * x * (1 - x);
}

// Normalizes the seed byte array into a double value in the [0, 1] range.
static double bm_init(uint8_t* seed) {
    // Turn the seed byte array into a 64-bit unsigned integer;
    uint64_t integer_value = 0;
    double double_value = 0.0;
    for (size_t i = 0; i < INTERNAL_SEED_LEN; i++) {
        integer_value |= (uint64_t)(seed[i] << i * 8);
    }
    // Normalize the integer value as a double in the [0, 1] range;
    double_value = (double)integer_value / (double)UINT64_MAX;
    return double_value;
}

// Iterates the bifurcation map until it reaches a chaotic state.
static void bm_warmup(double *x, double r) {
    for (size_t i = 0; i < BM_WARMUP_ITER; i++) {
        *x = bifurcation_map(*x, r);
    }
}

void bm_generate_entropy(uint8_t* key, size_t key_len) {
    // Set up the parameters and generate a seed;
    uint8_t initial_seed[INTERNAL_SEED_LEN] = { 0 };
    urandom(initial_seed);
    double r = 4.00;
    double x = bm_init(initial_seed);
    // Iterate the bifurcation map to reach a chaotic state;
    bm_warmup(&x, r);
    // Iterate the bifuraction map and extract one bit per loop;
    for (size_t i = 0; i < key_len; i++) {
        for (uint8_t j = 0; j < 8; j++) {
            x = bifurcation_map(x, r);
            // Transform into bit values;
            uint8_t rand_bit = (x >= 0.5) ? 1 : 0;
            key[i] = (key[i] << 1) | rand_bit;
        }
    }
    // Hash the key and return the hashed value (clipped if needed);
}
