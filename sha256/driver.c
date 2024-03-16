#include "sha256.h"
#include "../utils/general.h"

int main(int argc, char* argv[]) {
    sha256_testing("./test_vectors/SHA256ShortMsg.rsp");
    sha256_testing("./test_vectors/SHA256LongMsg.rsp");
    sha256_monte_carlo("./test_vectors/SHA256Monte.rsp");
    return 0;
}