#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <termios.h>
#include "common/common.c"
#include "pki/eccEG.c"
#include "hash/qx.c"
#include "ciphers/akms2_cbc.c"
#include "ciphers/chacha20.c"

/* DarkSafe */
/* by KryptoMagick (Karl Zander) */

void usage() {
    printf("DarkSafe v0.0.0 - by KryptoMagick\n\n");
    printf("Algorithms:\n***********\nakms2            256 bit\nchacha20         256 bit\n\n");
    printf("Usage:\nsafe <algorithm> -e <input file> <output file> <pk file>\n");
    printf("safe <algorithm> -d <input file> <output file> <sk file>\n");
}

int main(int argc, char *argv[]) {
    int kdf_iters = 100000;

    char *encrypt_symbol = "-e";
    char *decrypt_symbol = "-d";

    if (argc != 6) {
        usage();
        return 0;
    }

    FILE *infile, *outfile;
    char *infile_name, *outfile_name, *pkfile_name;
    char *algorithm = argv[1];
    char *mode = argv[2];
    infile_name = argv[3];
    outfile_name = argv[4];
    pkfile_name = argv[5];

    file_present(infile_name);
    file_present(pkfile_name);

    if (strcmp(algorithm, "akms2") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            akms2_cbc_encrypt(infile_name, outfile_name, pkfile_name);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            akms2_cbc_decrypt(infile_name, outfile_name, pkfile_name);
        }
    }
    else if (strcmp(algorithm, "chacha20") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            chacha_encrypt(infile_name, outfile_name, pkfile_name);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            chacha_decrypt(infile_name, outfile_name, pkfile_name);
        }
    }
    printf("\n");
    return 0;
}
