#include "general.h"

void print_bytes_hex(uint8_t* byte_array, size_t size) {
    for (size_t i = 0; i < size; i++) {
            printf("%2.2X", byte_array[i]);
        }
    printf("\n");
}

void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    errno = 0;
    if (ptr == NULL) {
        if (errno) {
            perror("Error in malloc()");
        } else {
            fputs("Unable to allocate enough memory!!\n", stderr);
        }
        exit(EXIT_FAILURE);
    }
    return ptr;
}