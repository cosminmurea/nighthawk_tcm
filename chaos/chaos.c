#include <stdio.h>
#include <string.h>
#include <math.h>
// For opening /dev/urandom;
#include <fcntl.h>
// For reading from and closing /dev/urandom;
#include <unistd.h>

#include "chaos.h"
#include "../sha256/sha256.h"
#include "../utils/general.h"

// The width in bytes of the value used as seed for each chaotic system;
#define INTERNAL_SEED_LEN 8
// The number of iterations for each system to reach a chaotic state;
#define WARMUP_ITER 100000
// The constants used in the Lorenz system;
#define LORENZ_SIGMA 10.0
#define LORENZ_RHO 28.0
#define LORENZ_BETA 8.0 / 3.0

static void urandom_seed(uint8_t* seed) {
    size_t sum = 0;
    uint8_t* digest = NULL;
    // Open /dev/urandom and save the file descriptor;
    int32_t urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd == -1) {
        fprintf(stderr, "Could not open /dev/urandom. Proceeding to crash. Cleaning up...");
        exit(EXIT_FAILURE);
    }
    // Extract 8 bytes different from 0x0000000000000000;
    while (sum == 0) {
        // Read 8 bytes from /dev/urandom and store them into the seed buffer;
        if (read(urandom_fd, seed, INTERNAL_SEED_LEN) != INTERNAL_SEED_LEN) {
            fprintf(stderr, "Could not read from /dev/urandom. Proceeding to crash. Cleaning up...");
            exit(EXIT_FAILURE);
        }
        // Check if 0 was generated (can it even generate 0??);
        for (size_t i = 0; i < INTERNAL_SEED_LEN; i++) {
            sum += seed[i];
        }
    }
    // Close /dev/urandom;
    close(urandom_fd);
    // Hash the seed to avoid exposing the entropy pool;
    sha256(seed, INTERNAL_SEED_LEN, &digest);
    // Use the middle 8 bytes of the digest as the seed;
    memcpy(seed, digest + 12, INTERNAL_SEED_LEN);
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

static void lorenz_system(double x, double y, double z, double* dx, double* dy, double* dz) {
    // Compute the derivatives at the given values;
    *dx = LORENZ_SIGMA * (y - x);
    *dy = x * (LORENZ_RHO - z) - y;
    *dz = x * y - LORENZ_BETA * z;
}

static void runge_kutta4(double x, double y, double z, double* new_x, double* new_y, double* new_z, double dt) {
    // Variables for storing intermediate slopes (4 interm. slopes for each coordinate);
    double k1_x, k2_x, k3_x, k4_x;
    double k1_y, k2_y, k3_y, k4_y;
    double k1_z, k2_z, k3_z, k4_z;
    // Evaluate 4 slopes at 4 different intermediate points in the interval;
    // First slope at the start of the interval;
    lorenz_system(x, y, z, &k1_x, &k1_y, &k1_z);
    // Second slope at a midpoint using the k1 slopes;
    // k2_x = f(x + 0.5 * k1_x * dt, y + 0.5 * k1_y * dt, z + 0.5 * k1_z * dt);
    lorenz_system(x + 0.5 * dt * k1_x, y + 0.5 * dt * k1_y, z + 0.5 * dt * k1_z, &k2_x, &k2_y, &k2_z);
    // Third slope at a second midpoint using the k2 slopes;
    lorenz_system(x + 0.5 * dt * k2_x, y + 0.5 * dt * k2_y, z + 0.5 * dt * k2_z, &k3_x, &k3_y, &k3_z);
    // Fourth slope at the end of the interval;
    lorenz_system(x + dt * k3_x, y + dt * k3_y, z + dt * k3_z, &k4_x, &k4_y, &k4_z);
    // Evaluate the next value using the weighted slopes;
    // The middle slopes weigh more than the other;
    *new_x = x + (dt / 6.0) * (k1_x + 2 * k2_x + 2 * k3_x + k4_x);
    *new_y = y + (dt / 6.0) * (k1_y + 2 * k2_y + 2 * k3_y + k4_y);
    *new_z = z + (dt / 6.0) * (k1_z + 2 * k2_z + 2 * k3_z + k4_z);
}

static void runge_kutta_fehlberg_45(double x, double y, double z, double* new_x, double* new_y, double* new_z, double* loc_trunc_err, double dt) {
    // Variables for the 6 intermediate slopes (6 instead of using 10);
    double k1x, k1y, k1z;
    double k2x, k2y, k2z;
    double k3x, k3y, k3z;
    double k4x, k4y, k4z;
    double k5x, k5y, k5z;
    double k6x, k6y, k6z;

    // Coefficients for slope estimation A(i,j);
    const double a21 = 1.0 / 4.0;
    const double a31 = 3.0 / 32.0;
    const double a32 = 9.0 / 32.0;
    const double a41 = 1932.0 / 2197.0;
    const double a42 = -7200.0 / 2197.0;
    const double a43 = 7296.0 / 2197.0;
    const double a51 = 439.0 / 216.0;
    const double a52 = -8.0;
    const double a53 = 3680.0 / 513.0;
    const double a54 = -845.0 / 4104.0;
    const double a61 = -8.0 / 27.0;
    const double a62 = 2.0;
    const double a63 = -3544.0 / 2565.0;
    const double a64 = 1859.0 / 4104.0;
    const double a65 = -11.0 / 40.0;

    // Compute 6 intermediate slopes for each variable => 18 total slopes;
    lorenz_system(x, y, z, &k1x, &k1y, &k1z);
    lorenz_system(
        x + a21 * dt * k1x,
        y + a21 * dt * k1y,
        z + a21 * dt * k1z,
        &k2x, &k2y, &k2z
    );
    lorenz_system(
        x + a31 * dt * k1x + a32 * dt * k2x,
        y + a31 * dt * k1y + a32 * dt * k2y,
        z + a31 * dt * k1z + a32 * dt * k2z,
        &k3x, &k3y, &k3z
    );
    lorenz_system(
        x + a41 * dt * k1x + a42 * dt * k2x + a43 * dt * k3x,
        y + a41 * dt * k1y + a42 * dt * k2y + a43 * dt * k3y,
        z + a41 * dt * k1z + a42 * dt * k2z + a43 * dt * k3z,
        &k4x, &k4y, &k4z
    );
    lorenz_system(
        x + a51 * dt * k1x + a52 * dt * k2x + a53 * dt * k3x + a54 * dt * k4x,
        y + a51 * dt * k1y + a52 * dt * k2y + a53 * dt * k3y + a54 * dt * k4y,
        z + a51 * dt * k1z + a52 * dt * k2z + a53 * dt * k3z + a54 * dt * k4z,
        &k5x, &k5y, &k5z
    );
    lorenz_system(
        x + a61 * dt * k1x + a62 * dt * k2x + a63 * dt * k3x + a64 * dt * k4x + a65 * dt * k5x,
        y + a61 * dt * k1y + a62 * dt * k2y + a63 * dt * k3y + a64 * dt * k4y + a65 * dt * k5y,
        z + a61 * dt * k1z + a62 * dt * k2z + a63 * dt * k3z + a64 * dt * k4z + a65 * dt * k5z,
        &k6x, &k6y, &k6z
    );

    // The weights used in determining the 5th order estimates;
    const double b1 = 16.0 / 135.0;
    const double b3 = 6656.0 / 12825.0;
    const double b4 = 28561.0 / 56430.0;
    const double b5 = -9.0 / 50.0;
    const double b6 = 2.0 / 55.0;

    // Compute the new value using the 5th order estimate;
    *new_x = x + dt * (b1 * k1x + b3 * k3x + b4 * k4x + b5 * k5x + b6 * k6x);
    *new_y = y + dt * (b1 * k1y + b3 * k3y + b4 * k4y + b5 * k5y + b6 * k6y);
    *new_z = z + dt * (b1 * k1z + b3 * k3z + b4 * k4z + b5 * k5z + b6 * k6z);

    // The coefficients used for computing the local truncation error for each variable;
    // In this case, the final coefficients are c_i = b_i - b'_i where b'_i are the 4th order coefficients;
    const double c1 = 1.0 / 360.0;
    const double c3 = -128.0 / 4275.0;
    const double c4 = -2197.0 / 75240.0;
    const double c5 = 1.0 / 50.0;
    const double c6 = 2.0 / 55.0;

    // The error is TE = (1 / dt) * | w - w' | where w is the 5th order value and w' is the 4th order value;
    double error_x = (1.0 / dt) * fabs(c1 * k1x + c3 * k3x + c4 * k4x + c5 * k5x + c6 * k6x);
    double error_y = (1.0 / dt) * fabs(c1 * k1y + c3 * k3y + c4 * k4y + c5 * k5y + c6 * k6y);
    double error_z = (1.0 / dt) * fabs(c1 * k1z + c3 * k3z + c4 * k4z + c5 * k5z + c6 * k6z);

    // Compute the error using the Euclidean vector norm;
    *loc_trunc_err = sqrt(error_x * error_x + error_y * error_y + error_z * error_z);
}

void lorenz_generator() {
    double x = 1.0, y = 1.0, z = 1.0;
    double next_x = 0.0, next_y = 0.0, next_z = 0.0;
    // Set the initial step size and total time;
    double dt = 0.01;
    double total_time = 1.0;
    // The smaller the tolerance the more accurate the results (but more intensive comp.);
    double tolerance = 1e-7;
    double loc_trunc_err = 0.0;
    // Scale the step size based on the error;
    double scale_factor = 0.0;
    // Run the simulation;
    while (total_time > 0) {
        // Perform one step of RKF45;
        runge_kutta_fehlberg_45(x, y, z, &next_x, &next_y, &next_z, &loc_trunc_err, dt);
        // Compare the local truncation error to the tolerance;
        // Update the values if the error is acceptable if not, scale the step size;
        if (loc_trunc_err < tolerance) {
            x = next_x;
            y = next_y;
            z = next_z;
            total_time -= dt;
            // TODO REMOVE ONCE DEBUGGING IS FINISHED;
            printf("Time = %lf, x = %.15f, y = %.15f, z = %.15f\n", 1.0 - total_time, x, y, z);
        }
        // Compute the scale factor based on the obtained error;
        // Let s = 0.84 * (tolerance / local_truncation_error)^(1/4);
        scale_factor = 0.84 * pow(tolerance / loc_trunc_err, 1.0 / 4.0);
        dt *= scale_factor;
    }
}

static double normalize(uint8_t* seed) {
    uint32_t integer_value = 0;
    double double_value = 0.0;
    // Turn the byte array into a 32-bit unsigned integer;
    for (size_t i = 0; i < INTERNAL_SEED_LEN / 2; i++) {
        integer_value |= (uint32_t)(seed[i] << i * 8);
    }
    double_value = (double)integer_value / (UINT32_MAX + 1.0);
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
    // Iterate the sine map to reach a chaotic state;
    for (size_t i = 0; i < WARMUP_ITER; i++) {
        *x = sine_map(*x, r);
    }
}

void generate_entropy(uint8_t* key, size_t key_len) {
    // Set up the r parameters;
    double r_lm = 4.00;
    double r_tent = 1.90;
    double r_sine = 1.00;
    // Generate and normalize the seeds;
    uint8_t seed_lm[INTERNAL_SEED_LEN] = { 0 };
    uint8_t seed_tent[INTERNAL_SEED_LEN] = { 0 };
    uint8_t seed_sine[INTERNAL_SEED_LEN] = { 0 };
    urandom_seed(seed_lm);
    urandom_seed(seed_tent);
    urandom_seed(seed_sine);
    double x_lm = normalize(seed_lm);
    double x_tent = normalize(seed_tent);
    double x_sine = normalize(seed_sine);
    double temp = 0.0;
    uint8_t rand_bit = 0;
    double reversed_x_lm = 0.0;
    char x_lm_str[18] = { 0 };
    char reversed_x_lm_str[18] = { 0 };
    // Stage 1: Warm the systems up;
    lm_warmup(&x_lm, r_lm);
    tent_warmup(&x_tent, r_tent);
    sine_warmup(&x_sine, r_sine);
    printf("X_LM =\t%1.15f\nX_TENT =\t%1.15f\nX_SINE =\t%1.15f\n", x_lm, x_tent, x_sine);
    // Stage 2: Generate key_len bytes using the systems;
    for (size_t i = 0; i < key_len; i++) {
        // Stage 2.1: Generate one byte;
        for (uint8_t j = 0; j < 8; j++) {
            // For all but the first iteration reverse the fractional part of x_lm;
            // This eventually leads to the degradation of reversed_x_lm (-> 0);
            // If this happens use x_lm instead;
            if ((j != 0) && (reversed_x_lm != 0.0)) {
                x_lm = logistics_map(reversed_x_lm, r_lm);
            } else {
                x_lm = logistics_map(x_lm, r_lm);
            }
            // Pool the tent map if x_lm < 0.5 and the sine map if x_lm >= 0.5;
            if (x_lm < 0.5) {
                x_tent = tent_map(x_tent, r_tent);
                temp = x_tent;
            } else {
                x_sine = sine_map(x_sine, r_sine);
                temp = x_sine;
            }
            rand_bit = (temp >= 0.5) ? 1 : 0;
            key[i] = (key[i] << 1) | rand_bit;
            // Reverse the fractional part of x_lm with .15 precision;
            // Ex: frac_rev(0.12...34) = 0.43...21;
            reversed_x_lm = x_lm;
            snprintf(x_lm_str, 18, "%1.15f", reversed_x_lm);
            snprintf(reversed_x_lm_str, 18, "%1.15f", reversed_x_lm);
            for (size_t i = 0; i < 15; i++) {
                reversed_x_lm_str[i + 2] = x_lm_str[18 - 2 - i];
            }
            reversed_x_lm = strtod(reversed_x_lm_str, NULL);
        }
        printf("X_LM =\t\t%1.15f\nREV_X_LM =\t%1.15f\n", x_lm, reversed_x_lm);
    }
}

double lm_lyapunov_exp(double r) {
    uint8_t seed[INTERNAL_SEED_LEN] = { 0 };
    urandom_seed(seed);
    double x = normalize(seed);
    double sum = 0.0;
    double lm_prime_x = 0.0;
    double lyapunov_exp = 0.0;
    // Compute the Lyapunov exponent of the sample;
    for (size_t i = 0; i < WARMUP_ITER; i++) {
        lm_prime_x = logistics_map_prime(x, r);
        x = logistics_map(x, r);
        sum += log(fabs(lm_prime_x));
    }
    lyapunov_exp = sum / (double) WARMUP_ITER;
    return lyapunov_exp;
}

double tent_lyapunov_exp(double r) {
    uint8_t seed[INTERNAL_SEED_LEN] = { 0 };
    urandom_seed(seed);
    double x = normalize(seed);
    double sum = 0.0;
    double tent_prime_x = 0.0;
    double lyapunov_exp = 0.0;
    // Compute the Lyapunov exponent of the sample;
    for (size_t i = 0; i < WARMUP_ITER; i++) {
        tent_prime_x = tent_map_prime(r);
        x = tent_map(x, r);
        sum += log(fabs(tent_prime_x));
    }
    lyapunov_exp = sum / (double) WARMUP_ITER;
    return lyapunov_exp;
}

double sine_lyapunov_exp(double r) {
    uint8_t seed[INTERNAL_SEED_LEN] = { 0 };
    urandom_seed(seed);
    double x = normalize(seed);
    double sum = 0.0;
    double sine_prime_x = 0.0;
    double lyapunov_exp = 0.0;
    // Compute the Lyapunov exponent of the sample;
    for (size_t i = 0; i < WARMUP_ITER; i++) {
        sine_prime_x = sine_map_prime(x, r);
        x = sine_map(x, r);
        sum += log(fabs(sine_prime_x));
    }
    lyapunov_exp = sum / (double) WARMUP_ITER;
    return lyapunov_exp;
}

static void byte_array_prob(uint8_t* byte_array, size_t array_len, double* prob) {
    int freq[array_len];
    int counter = 1;
    // Initialise the frequency array to -1;
    for (size_t i = 0; i < array_len; i++) {
        freq[i] = -1;
    }
    // Compute the frequencies of the elements;
    for (size_t i = 0; i < array_len; i++) {
        counter = 1;
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