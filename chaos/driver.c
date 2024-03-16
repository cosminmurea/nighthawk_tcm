#include <stdio.h>
#include "entropy.h"

int main() {
    // uint8_t sample[100000];
    // // Check the Shannon entropy of the logistics map;
    // lm_generate_entropy(sample, 100000);
    // double entropy = shannon_entropy(sample, 100000);
    // printf("The Shannon entropy of the system is %f bits\n", entropy);
    double lyap = lm_lyapunov_exp(4.0);
    printf("The Lyapunov exponent of the system is %f \n", lyap);
    return 0;
}