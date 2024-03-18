#include "rsa.h"

int main() {
    char p[] = "618970019642690137449562111";
    char q[] = "162259276829213363391578010288127";
    char e[] = "170141183460469231731687303715884105727";
    uint8_t msg[3] = { 0x61, 0x62, 0x63 };
    rsa(msg, 3, p, q, e);
    // mpz_t p, q, n, e, d;
    // mpz_inits(p, q, n, e, d, NULL);
    // mpz_set_str(p, "618970019642690137449562111", 10);
    // mpz_set_str(q, "162259276829213363391578010288127", 10);
    // mpz_set_str(n, "0", 10);
    // mpz_set_str(e, "0", 10);
    // mpz_set_str(d, "0", 10);
    // rsa_generate_keys(p, q, n, e, d);
    return 0;
}