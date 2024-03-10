#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include "entropy.h"

// Length of the internal seed used as initial value for the chaotic systems;
#define INTERNAL_SEED_LEN 8
// The number of iterations for a chaotic system to reach a chaotic state;
#define WARMUP_ITER 10000

static void urandom_seed(uint8_t* seed) {
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

// Implements the logistics map x(n + 1) = r * x(n) * (1 - x(n)).
static double logistics_map(double x, double r) {
    return r * x * (1 - x);
}

static double normalize(uint8_t* seed) {
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

// Iterates the logistics map until it reaches a chaotic state.
static void lm_warmup(double *x, double r) {
    for (size_t i = 0; i < WARMUP_ITER; i++) {
        *x = logistics_map(*x, r);
    }
}

void lm_generate_entropy(uint8_t* key, size_t key_len) {
    // Set up the r parameter and generate a random x0;
    uint8_t seed[INTERNAL_SEED_LEN] = { 0 };
    urandom(seed);
    double r = 4.00;
    double x = normalize(seed);
    // Iterate the logistics map to reach a chaotic state;
    lm_warmup(&x, r);
    // Iterate the logistics map and extract one bit per loop;
    for (size_t i = 0; i < key_len; i++) {
        for (uint8_t j = 0; j < 8; j++) {
            x = logistics_map(x, r);
            // Transform into bit values;
            uint8_t rand_bit = (x >= 0.5) ? 1 : 0;
            key[i] = (key[i] << 1) | rand_bit;
        }
    }
}
