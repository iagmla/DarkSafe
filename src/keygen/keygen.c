#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ecceg_keygen(int psize, char * prefix) {
    struct ecc_elgamal_ctx ctx;
    ecc_keygen(&ctx);
    printf("ECC El Gamal encryption public keys generated successfully.\n");

    pkg_pk(&ctx, prefix);
    pkg_sk(&ctx, prefix);
}
