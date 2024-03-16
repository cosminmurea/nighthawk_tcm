#include <stdio.h>
#include <string.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include "entropy.h"
#include "../sha256/sha256.h"
#include "../utils/general.h"

// Length of the seed used as initial value for the chaotic systems;
#define INTERNAL_SEED_LEN 8
// The number of iterations for a system to reach a chaotic state;
#define WARMUP_ITER 1000000

static void urandom_seed(uint8_t* seed) {
    // Open /dev/urandom and save the file descriptor;
    int32_t urandom_fd = open("/dev/urandom", O_RDONLY);
    uint32_t* digest = NULL;
    if (urandom_fd == -1) {
        fprintf(stderr, "Could not open /dev/urandom. Proceeding to crash. Cleaning up...");
        exit(EXIT_FAILURE);
    }
    // Read 8 bytes from /dev/urandom and store them into the seed buffer;
    if (read(urandom_fd, seed, INTERNAL_SEED_LEN) != INTERNAL_SEED_LEN) {
        fprintf(stderr, "Could not read from /dev/urandom. Proceeding to crash. Cleaning up...");
        exit(EXIT_FAILURE);
    }
    close(urandom_fd);
    // Hash the seed to avoid exposing the entropy pool;
    sha256(seed, INTERNAL_SEED_LEN, &digest);
    sha256_print_digest(digest);
    ltb_endian_conv32_array(digest, 8);
    memcpy(seed, digest + 3, 8);
    print_byte_array(seed, 8);
    free(digest);
}

static double logistics_map(double x, double r) {
    return r * x * (1 - x);
}

static double logistics_map_prime(double x, double r) {
    return r * (1 - 2 * x);
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

static void lm_warmup(double *x, double r) {
    // Iterate the logistics map to reach a chaotic state;
    for (size_t i = 0; i < WARMUP_ITER; i++) {
        *x = logistics_map(*x, r);
    }
}

void lm_generate_entropy(uint8_t* key, size_t key_len) {
    // Set up the r parameter and generate a random seed;
    double r = 4.00;
    uint8_t seed[INTERNAL_SEED_LEN] = { 0 };
    urandom_seed(seed);
    double x = normalize(seed);
    // Reach a chaotic state with the given parameters;
    lm_warmup(&x, r);
    // Extract one bit from each iteration of the logistics map;
    for (size_t i = 0; i < key_len; i++) {
        for (uint8_t j = 0; j < 8; j++) {
            x = logistics_map(x, r);
            // Transform into bit values;
            // Comparison bias??
            uint8_t rand_bit = (x >= 0.5) ? 1 : 0;
            key[i] = (key[i] << 1) | rand_bit;
        }
    }
}

double lm_lyapunov_exp(double r) {
    double sum = 0.0;
    uint8_t seed[INTERNAL_SEED_LEN] = { 0 };
    urandom_seed(seed);
    double x = normalize(seed);
    double lyapunov_exp = 0.0;
    for (size_t i = 0; i < WARMUP_ITER; i++) {
        double f_prime_x = logistics_map_prime(x, r);
        x = logistics_map(x, r);
        sum += log(fabs(f_prime_x));
    }
    lyapunov_exp = sum / (double) WARMUP_ITER;
    return lyapunov_exp;
}

static void byte_array_prob(uint8_t* byte_array, size_t array_len, double* prob) {
    int freq[array_len];
    // Initialise the frequency array to -1;
    for (size_t i = 0; i < array_len; i++) {
        freq[i] = -1;
    }
    // print_byte_array(byte_array, array_len);
    // Compute the frequencies for the byte array;
    for (size_t i = 0; i < array_len; i++) {
        // printf("%X\n", byte_array[i]);
        int counter = 1;
        for (size_t j = i + 1; j < array_len; j++) {
            if (byte_array[i] == byte_array[j]) {
                counter++;
                // If a byte has freq > 1, the next occurrences will get a freq of 0;
                freq[j] = 0;
            }
        }
        if (freq[i] == -1) {
            freq[i] = counter;
        }
    }
    // Compute the probability of each byte;
    for (size_t i = 0; i < array_len; i++) {
        prob[i] = (double)freq[i] / array_len;
    }
}

double shannon_entropy(uint8_t* sample, size_t sample_len) {
    double prob[sample_len];
    double shannon_entropy = 0.0;
    size_t count = 0;
    // Generate a large sample;
    byte_array_prob(sample, sample_len, prob);
    // Print the probabilities of the sample;
    for (size_t i = 0; i < sample_len; i++) {
        if (prob[i] != 0) {
            printf("Count: %zu \tProb: \t%f\n", count++, prob[i]);
        }
    }
    printf("\n");
    // Compute the Shannon entropy of the sample;
    for (size_t i = 0; i < sample_len; i++) {
        if (prob[i] != 0) {
            shannon_entropy -= prob[i] * log2(prob[i]);
        }
    }
    return shannon_entropy;
}
