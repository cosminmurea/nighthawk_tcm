#include <string.h>
#include "sha256.h"
#include "../utils/general.h"

#define SHA256_MAX_TEST_MSG_LENGTH 13000
#define SHA256_MC_ITERATIONS 100001
#define SHA256_MC_MAX_TEST_MSG_LENGTH 100
#define SHA256_MC_POOL_INTERVAL 1000

// The first 32 bits of the fractional parts of the cube roots of the first 64 primes;
const uint32_t round_constants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t right_rotate(uint32_t x, size_t k) {
    return ((x >> k) | (x << (32 - k)));
}

static uint32_t choice(uint32_t x, uint32_t y, uint32_t z) {
    // If x then y else z;
    return ((x & y) ^ (~x & z));
}

static uint32_t majority(uint32_t x, uint32_t y, uint32_t z) {
    // True if at least 2 elements are true;
    return ((x & y) ^ (x & z) ^ (y & z));
}

static uint32_t sigma0(uint32_t x) {
    return (right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22));
}

static uint32_t sigma1(uint32_t x) {
    return (right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25));
}

static uint32_t delta0(uint32_t x) {
    return (right_rotate(x, 7) ^ right_rotate(x, 18) ^ (x >> 3));
}

static uint32_t delta1(uint32_t x) {
    return (right_rotate(x, 17) ^ right_rotate(x, 19) ^ (x >> 10));
}

static void sha256_padding(const uint8_t* data, size_t data_len, uint8_t** padded, size_t* padded_len) {
    size_t total_zeros = 0;
    uint64_t bit_length = 0;

    // When the message is 9 bytes short of a block multiple there is no additional block added;
    if ((data_len + 9) % SHA256_BLOCK_SIZE == 0) {
        *padded_len = data_len + 9;
    } else {
        *padded_len = ((data_len + 9 + SHA256_BLOCK_SIZE) / SHA256_BLOCK_SIZE) * SHA256_BLOCK_SIZE;
    }
    *padded = safe_malloc((*padded_len * sizeof **padded));
    memcpy(*padded, data, data_len);

    // Add the 1 bit as big-endian using the byte 0x80 = 0b10000000;
    (*padded)[data_len] = 0x80;
    // Compute and add the needed amount of 0 bits to reach congruence modulo 448;
    total_zeros = *padded_len - data_len - 9;
    memset((*padded + data_len + 1), 0x00, total_zeros);

    // Add the length of the message in bits as a big-endian 64-bit value;
    bit_length = (uint64_t)data_len * 8;
    for (size_t i = 0; i < 8; i++) {
        (*padded)[*padded_len - 8 + i] = (uint8_t)(bit_length >> (56 - i * 8));
    }
}

static void sha256_compression(const uint8_t* block, uint32_t* hash) {
    uint32_t a = hash[0];
    uint32_t b = hash[1];
    uint32_t c = hash[2];
    uint32_t d = hash[3];
    uint32_t e = hash[4];
    uint32_t f = hash[5];
    uint32_t g = hash[6];
    uint32_t h = hash[7];
    uint32_t temp1, temp2;
    uint32_t msg_schedule[SHA256_BLOCK_SIZE];

    // The 64 bytes in the block are used as the first 16 words of the message schedule;
    for (size_t i = 0, j = 0; i < 16; i++, j += 4) {
        // Interpret 4 bytes as a 32 bit value;
        msg_schedule[i] = (block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | (block[j + 3]);
    }

    // Use the S-Box functions to generate another 48 message schedule words;
    for (size_t i = 16; i < 64; i++) {
        msg_schedule[i] = delta1(msg_schedule[i - 2]) + msg_schedule[i - 7] + delta0(msg_schedule[i - 15]) + msg_schedule[i - 16];
    }

    // Use the S-Box functions, round constants and the message schedule for compression;
    for (size_t i = 0; i < 64; i++) {
        temp1 = h + sigma1(e) + choice(e, f, g) + round_constants[i] + msg_schedule[i];
        temp2 = sigma0(a) + majority(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // Save the intermediate / final hash values;
    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
}

void sha256(const uint8_t* data, size_t data_len, uint32_t** digest) {
    uint8_t* padded = NULL;
    size_t padded_len = 0;

    // The first 32 bits of the fractional parts of the square roots of the first 8 primes;
    uint32_t hash[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // Store the final value on the heap;
    *digest = safe_malloc(8 * sizeof **digest);
    // Pad the message to a multiple of 512 bits;
    sha256_padding(data, data_len, &padded, &padded_len);

    // Apply the compression function on every block;
    for (size_t i = 0; i < padded_len / SHA256_BLOCK_SIZE; i++) {
        sha256_compression((padded + i * SHA256_BLOCK_SIZE), hash);
    }

    for (size_t i = 0; i < 8; i++) {
        (*digest)[i] = hash[i];
    }
    // Convert the digest to a byte array before returning it;
    free(padded);
}

void sha256_print_digest(uint32_t* digest) {
    for (size_t i = 0; i < 8; i++) {
        printf("%08x", digest[i]);
    }
    printf("\n\n");
}

void sha256_to_byte_array(const uint32_t* digest, uint8_t** byte_array) {
    *byte_array = safe_malloc(SHA256_DIGEST_SIZE * sizeof **byte_array);
    le_to_be_v32(digest, SHA256_DIGEST_SIZE / 4);
    memcpy(byte_array, digest, SHA256_DIGEST_SIZE);
}

void sha256_testing(const char* test_file) {
    FILE* file_ptr = safe_fopen(test_file, "rb");
    char buffer[SHA256_MAX_TEST_MSG_LENGTH] = {0};
    uint8_t* hex_message = NULL;
    size_t message_length = 0;
    uint32_t* digest = NULL;

    // Skip the first 7 lines of the file;
    for (size_t i = 0; i < 7; i++) {
        fgets(buffer, SHA256_MAX_TEST_MSG_LENGTH, file_ptr);
    }
    memset(buffer, 0, SHA256_MAX_TEST_MSG_LENGTH);

    // Read the file in groups of 4 lines;
    while (fgets(buffer, SHA256_MAX_TEST_MSG_LENGTH, file_ptr)) {
        // Read the length L in bits (line 1);
        sscanf(buffer, "Len = %zu", &message_length);
        printf("Length : \t%zu bytes.\n", message_length / 8);
        memset(buffer, 0, SHA256_MAX_TEST_MSG_LENGTH);

        // Read the message as a string of hex characters (line 2);
        fgets(buffer, SHA256_MAX_TEST_MSG_LENGTH, file_ptr);
        sscanf(buffer, "Msg = %s", buffer);
        // Turn the hex string into a byte array;
        hex_message = hex_to_byte_array(buffer, message_length / 4);
        memset(buffer, 0, SHA256_MAX_TEST_MSG_LENGTH);

        // Read the NIST provided digest (line 3);
        fgets(buffer, SHA256_MAX_TEST_MSG_LENGTH, file_ptr);
        sscanf(buffer, "MD = %s", buffer);
        printf("NIST Digest : \t%s\n", buffer);
        memset(buffer, 0, SHA256_MAX_TEST_MSG_LENGTH);

        // Every fourth line is empty => read and discard;
        fgets(buffer, SHA256_MAX_TEST_MSG_LENGTH, file_ptr);
        memset(buffer, 0, SHA256_MAX_TEST_MSG_LENGTH);

        // Compute and print the local digest;
        printf("Local Digest : \t");
        sha256(hex_message, message_length / 8, &digest);
        sha256_print_digest(digest);
    }
    fclose(file_ptr);
    free(hex_message);
    free(digest);
}

void sha256_monte_carlo(const char* test_file) {
    FILE* file_ptr = safe_fopen(test_file, "rb");
    char buffer[SHA256_MC_MAX_TEST_MSG_LENGTH] = { 0 };
    uint8_t temp[SHA256_MC_MAX_TEST_MSG_LENGTH] = { 0 };
    uint8_t* seed = NULL;
    uint32_t* digest = NULL;
    size_t count = 0;

    // Skip the first 7 lines of the file;
    for (size_t i = 0; i < 7; i++) {
        fgets(buffer, SHA256_MC_MAX_TEST_MSG_LENGTH, file_ptr);
    }

    // Read the initial seed;
    fgets(buffer, SHA256_MC_MAX_TEST_MSG_LENGTH, file_ptr);
    sscanf(buffer, "Seed = %s", buffer);
    printf("Seed : \t\t%s\n", buffer);
    seed = hex_to_byte_array(buffer, SHA256_BLOCK_SIZE);
    memset(buffer, 0, SHA256_MC_MAX_TEST_MSG_LENGTH);

    // The next line is empty => read and discard;
    fgets(buffer, SHA256_MC_MAX_TEST_MSG_LENGTH, file_ptr);
    memset(buffer, 0, SHA256_MC_MAX_TEST_MSG_LENGTH);

    // Concatenate the seed three times to create the initial message;
    for (size_t i = 0; i < 3; i++) {
        memcpy(temp + i * SHA256_DIGEST_SIZE, seed, SHA256_DIGEST_SIZE);
    }

    // Compute 100.000 iterations;
    for (size_t i = 1; i < SHA256_MC_ITERATIONS; i++) {
        // Hash the current message;
        sha256(temp, 96, &digest);

        // Every 1000th iteration compare to the values in the file;
        if ((i % SHA256_MC_POOL_INTERVAL == 0) && (i != 0)) {
            // Read and print the count (line 1);
            fgets(buffer, SHA256_MC_MAX_TEST_MSG_LENGTH, file_ptr);
            sscanf(buffer, "COUNT = %zu", &count);
            printf("COUNT : \t%zu\n", count);
            memset(buffer, 0, SHA256_MC_MAX_TEST_MSG_LENGTH);

            // Read and print the NIST provided digest (line 2);
            fgets(buffer, SHA256_MC_MAX_TEST_MSG_LENGTH, file_ptr);
            sscanf(buffer, "MD = %s", buffer);
            printf("NIST Digest : \t%s\n", buffer);
            memset(buffer, 0, SHA256_MC_MAX_TEST_MSG_LENGTH);

            // Every third line is empty => read and discard;
            fgets(buffer, SHA256_MC_MAX_TEST_MSG_LENGTH, file_ptr);
            memset(buffer, 0, SHA256_MC_MAX_TEST_MSG_LENGTH);

            //// Print the message for debugging purposes;
            // printf("Current Message : \t");
            // print_byte_array(temp, 96);
            // Print the local digest;

            printf("Local Digest : \t");
            sha256_print_digest(digest);
        }

        // Convert the local digest to big-endian;
        le_to_be_v32(digest, SHA256_DIGEST_SIZE / 4);

        // Every 1000 iterations, the new initial message is the last digest concatenated 3 times;
        if (i % SHA256_MC_POOL_INTERVAL == 0) {
            for (size_t j = 0; j < 3; j++) {
                memcpy(temp + j * SHA256_DIGEST_SIZE, digest, SHA256_DIGEST_SIZE);
            }
        } else {
            // Left shift the message by one block and add the current digest as the third block;
            // Move the second block to the first position;
            memcpy(temp, temp + SHA256_DIGEST_SIZE, SHA256_DIGEST_SIZE);
            // Move the third block to the second position;
            memcpy(temp + SHA256_DIGEST_SIZE, temp + 2 * SHA256_DIGEST_SIZE, SHA256_DIGEST_SIZE);
            // Copy the current digest as the last block;
            memcpy(temp + 2 * SHA256_DIGEST_SIZE, digest, SHA256_DIGEST_SIZE);
        }
    }
    fclose(file_ptr);
    free(seed);
    free(digest);
}