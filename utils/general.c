#include <string.h>
#include <sys/stat.h>
#include "general.h"

void print_byte_array(const uint8_t* byte_array, size_t size) {
    for (size_t i = 0; i < size; i++) {
            printf("%2.2X", byte_array[i]);
        }
    printf("\n");
}

static uint8_t hex_to_byte(const char hex_char) {
    if (hex_char >= '0' && hex_char <= '9') {
        return hex_char - '0';
    } else if (hex_char >= 'a' && hex_char <= 'f') {
        return 10 + (hex_char - 'a');
    } else if (hex_char >= 'A' && hex_char <= 'F') {
        return 10 + (hex_char - 'A');
    }
    return -1;
}

uint8_t* hex_to_byte_array(const char* hex_string, size_t hex_len) {
    size_t byte_len = (hex_len + 1) / 2;
    uint8_t* byte_array = safe_malloc((byte_len * sizeof *byte_array));
    memset(byte_array, 0, byte_len);
    size_t hex_index = 0;
    size_t byte_index = 0;
    // Prepend a 0 nibble if the length of the hex string is odd;
    if (hex_len % 2 != 0) {
        uint8_t high_nibble = 0;
        uint8_t low_nibble = hex_to_byte(hex_string[hex_index++]);
        byte_array[byte_index++] = (uint8_t)((high_nibble << 4) | low_nibble);
    }
    // Every two hex digits form a single byte;
    for (size_t i = hex_index; i < hex_len; i += 2) {
        uint8_t high_nibble = hex_to_byte(hex_string[i]);
        uint8_t low_nibble = hex_to_byte(hex_string[i + 1]);
        byte_array[byte_index++] = (uint8_t)((high_nibble << 4) | low_nibble);
    }
    return byte_array;
}

uint64_t byte_array_to_uint64(const uint8_t* byte_array) {
    uint64_t value = 0;
    for (size_t i = 0; i < sizeof(uint64_t); i++) {
        value |= (uint64_t)(byte_array[i] << i * 8);
    }
    return value;
}

void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (ptr == NULL) {
        fprintf(stderr, "Could not allocate memory. Proceeding to crash. Cleaning up...");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

FILE* safe_fopen(const char* file_path, const char* mode) {
    FILE* file_ptr = fopen(file_path, mode);
    if (file_ptr == NULL) {
        fprintf(stderr, "Could not allocate memory. Proceeding to crash. Cleaning up...");
        exit(EXIT_FAILURE);
    }
    return file_ptr;
}

static size_t file_size(const char* file_path) {
    struct stat file_info;
    if (stat(file_path, &file_info) < 0) {
        fprintf(stderr, "Could not obtain file details. Proceeding to crash. Cleaning up...");
        exit(EXIT_FAILURE);
    }
    return file_info.st_size;
}

void file_to_byte_array(const char* file_path, uint8_t** buffer, size_t* buffer_len) {
    FILE* file_ptr = safe_fopen(file_path, "rb");
    *buffer_len = file_size(file_path);
    *buffer = safe_malloc(*buffer_len * sizeof **buffer);
    // Read from the file and check the amount of bytes read;
    size_t bytes_read = fread(*buffer, 1, *buffer_len, file_ptr);
    if (bytes_read != *buffer_len) {
        fprintf(stderr, "Could not read from the file. Proceeding to crash. Cleaning up...");
        exit(EXIT_FAILURE);
    }
    fclose(file_ptr);
}

static uint32_t ltb_endian_conv32(uint32_t value) {
    uint32_t big_endian_value = 0;
    uint32_t bytes[4] = { 0 };
    bytes[0] = (value & 0x000000FF) << 24;
    bytes[1] = (value & 0x0000FF00) << 8;
    bytes[2] = (value & 0x00FF0000) >> 8;
    bytes[3] = (value & 0xFF000000) >> 24;
    big_endian_value = bytes[0] | bytes[1] | bytes[2] | bytes[3];
    return big_endian_value;
}

void ltb_endian_conv32_array(uint32_t* array, size_t array_len) {
    for (size_t i = 0; i < array_len; i++) {
        array[i] = ltb_endian_conv32(array[i]);
    }
}