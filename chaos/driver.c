#include <stdio.h>
#include "chaos.h"

int main() {
    // uint8_t sample[100000];
    // generate_entropy(sample, 100000);
    // double entropy = shannon_entropy(sample, 100000);
    // printf("The Shannon entropy of the system is %f bits\n", entropy);
    // double r_lm = 4.0;
    // double r_tent = 2.00;
    // double r_sine = 1.00;
    // double lyap_lm = lm_lyapunov_exp(r_lm);
    // double lyap_tent = tent_lyapunov_exp(r_tent);
    // double lyap_sine = sine_lyapunov_exp(r_sine);
    // printf("The Lyapunov exponent of the logistics map for r = %f is %f \n", r_lm, lyap_lm);
    // printf("The Lyapunov exponent of the tent map for r = %f is %f \n", r_tent, lyap_tent);
    // printf("The Lyapunov exponent of the sine map for r = %f is %f \n", r_sine, lyap_sine);
    lorenz_generator();
    return 0;
}