#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <float.h>
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
    uint8_t* digest = NULL;

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
    print_byte_array(digest, SHA256_DIGEST_SIZE);
    memcpy(seed, digest + 12, INTERNAL_SEED_LEN);
    print_byte_array(seed, 8);
    free(digest);
}

static double logistics_map(double x, double r) {
    return r * x * (1 - x);
}

static double tent_map(double x, double r) {
    if (x < 0.5) {
        return r * x;
    } else {
        return r * (1 - x);
    }
}

static double sine_map(double x, double r) {
    return r * sin(M_PI * x);
}

static double logistics_map_prime(double x, double r) {
    return r * (1 - 2 * x);
}

static double tent_map_prime(double r) {
    return r;
}

static double sine_map_prime(double x, double r) {
    return r * M_PI * cos(M_PI * x);
}

static double normalize(uint8_t* seed) {
    uint32_t integer_value = 0;
    double double_value = 0.0;

    // Turn the seed byte array into a 32-bit unsigned integer;
    for (size_t i = 0; i < 4; i++) {
        integer_value |= (uint64_t)(seed[i] << i * 8);
    }

    double_value = (double)integer_value / ((double)UINT32_MAX + 1.0);
    return double_value;
}

static void lm_warmup(double* x, double r) {
    // Iterate the logistics map to reach a chaotic state;
    for (size_t i = 0; i < WARMUP_ITER; i++) {
        *x = logistics_map(*x, r);
    }
}

static void tent_warmup(double* x, double r) {
    // Iterate the tent map to reach a chaotic state;
    for (size_t i = 0; i < WARMUP_ITER; i++) {
        *x = tent_map(*x, r);
    }
}

static void sine_warmup(double* x, double r) {
    // Iterate the tent map to reach a chaotic state;
    for (size_t i = 0; i < WARMUP_ITER; i++) {
        *x = sine_map(*x, r);
    }
}

void generate_entropy(uint8_t* key, size_t key_len) {
    // Set up the r parameter and generate a random seed for x0;
    double r_lm = 4.00;
    double r_tent = 2.00;
    double r_sine = 1.00;
    uint8_t seed_lm[INTERNAL_SEED_LEN] = { 0 };
    uint8_t seed_tent[INTERNAL_SEED_LEN] = { 0 };
    uint8_t seed_sine[INTERNAL_SEED_LEN] = { 0 };
    urandom_seed(seed_lm);
    urandom_seed(seed_tent);
    urandom_seed(seed_sine);
    double x_lm = normalize(seed_lm);
    double x_tent = normalize(seed_tent);
    double x_sine = normalize(seed_sine);
    printf("x_lm = %f x_tent = %f x_sine = %f\n", x_lm, x_tent, x_sine);
    double temp = 0.0;
    double reversed_x_lm = 0.0;

    // Reach a chaotic state with the given parameters;
    lm_warmup(&x_lm, r_lm);
    tent_warmup(&x_tent, r_tent);
    sine_warmup(&x_sine, r_sine);
    printf("x_lm = %f x_tent = %f x_sine = %f\n", x_lm, x_tent, x_sine);

    // Generate key_len bytes;
    for (size_t i = 0; i < key_len; i++) {
        // Generate one byte;
        for (uint8_t j = 0; j < 8; j++) {
            x_lm = logistics_map(x_lm, r_lm);
            // Based on x_lm, either the sine or the tent maps are clocked;
            // r_sine = 1.00; r_tent = 2.00; r_lm = 4.00;
            // if (j != 0) {
            //     x_lm = logistics_map(reversed_x_lm, r_lm);
            // } else {
            //     x_lm = logistics_map(x_lm, r_lm);
            // }
            if (x_lm < 0.5) {
                x_tent = tent_map(x_tent, r_tent);
                temp = x_tent;
            } else {
                x_sine = sine_map(x_sine, r_sine);
                temp = x_sine;
            }
            // Transform into bit values;
            uint8_t rand_bit = (temp >= 0.5) ? 1 : 0;
            key[i] = (key[i] << 1) | rand_bit;
            // reversed_x_lm = x_lm;
            // char buffer[9] = { 0 };
            // double int_part = 0;
            // double frac_part = modf(reversed_x_lm, &int_part);
            // snprintf(buffer, 9, "%f", frac_part);
            // printf("Count = %d x_lm = %f rev_x_lm = %f buffer = %s\n", j, x_lm, reversed_x_lm, buffer);
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

double tent_lyapunov_exp(double r) {
    double sum = 0.0;
    uint8_t seed[INTERNAL_SEED_LEN] = { 0 };
    urandom_seed(seed);
    double x = normalize(seed);
    double lyapunov_exp = 0.0;

    for (size_t i = 0; i < WARMUP_ITER; i++) {
        double f_prime_x = tent_map_prime(r);
        x = tent_map(x, r);
        sum += log(fabs(f_prime_x));
    }

    lyapunov_exp = sum / (double) WARMUP_ITER;
    return lyapunov_exp;
}

double sine_lyapunov_exp(double r) {
    double sum = 0.0;
    uint8_t seed[INTERNAL_SEED_LEN] = { 0 };
    urandom_seed(seed);
    double x = normalize(seed);
    double lyapunov_exp = 0.0;

    for (size_t i = 0; i < WARMUP_ITER; i++) {
        double f_prime_x = sine_map_prime(x, r);
        x = sine_map(x, r);
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

    // Compute the frequencies for the byte array;
    for (size_t i = 0; i < array_len; i++) {
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

    // Compute and print the probabilities of the sample;
    byte_array_prob(sample, sample_len, prob);
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