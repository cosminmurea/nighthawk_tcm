#include <stdio.h>
#include "entropy.h"

int main() {
    uint8_t sample[1000];
    // Check the Shannon entropy of the logistics map;
    lm_generate_entropy(sample, 1000);
    double entropy = shannon_entropy(sample, 1000);
    printf("The Shannon entropy of the system is %f bits\n", entropy);
    return 0;
}