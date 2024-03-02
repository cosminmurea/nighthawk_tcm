#include "sha256.h"

int main(int argc, char* argv[]) {

    // If the first argument is the -t flag, the NIST test suite will be run.
    // Else the first argument is the path to a file.
    if (strcmp(argv[1], "-t") == 0) {
        sha256_testing("./test_vectors/SHA256ShortMsg.rsp");
        sha256_testing("./test_vectors/SHA256LongMsg.rsp");
    } else {
        uint8_t* message = NULL;
        size_t message_length = 0;
        read_file_bytes(argv[1], &message, &message_length);
        sha256(message, message_length);
        free(message);
    }

    return 0;
}