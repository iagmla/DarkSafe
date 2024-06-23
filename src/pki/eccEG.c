#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bn.h>

/* Elliptic Curve El Gamal 521 bit */
/* Implemenation by KryptoMagick (Karl Zander) */
/* Key Encapsulation Method */

struct ecc_elgamal_ctx {
    BIGNUM *sk;
    BIGNUM *pk;
    BIGNUM *bp;
};

void ecceg_encrypt(struct ecc_elgamal_ctx * ctx, BIGNUM *ctxt1, BIGNUM *ctxt2, const BIGNUM *ptxt) {
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *curve_point;
    curve_point = BN_new();
    BIGNUM *curve_point_minus_one;
    curve_point_minus_one = BN_new();
    BIGNUM *two;
    two = BN_new();
    BIGNUM *five_two_one;
    five_two_one = BN_new();
    BN_set_word(two, 2);
    BN_set_word(five_two_one, 521);
    BIGNUM *z1;
    z1 = BN_new();
    BN_one(z1);
    BIGNUM *ephemeral_key;
    ephemeral_key = BN_new();
    BIGNUM *tmp;
    tmp = BN_new();
    int r0 = BN_exp(curve_point, two, five_two_one, bnctx);
    r0 = BN_sub(curve_point, curve_point, z1);
    BN_sub(curve_point_minus_one, curve_point, z1);
    BN_rand_range(ephemeral_key, curve_point_minus_one);
    r0 = BN_mod_mul(ctxt1, ephemeral_key, ctx->bp, curve_point, bnctx);
    if (r0 == 0) {
        r0 = BN_mod_mul(ctxt1, ephemeral_key, ctx->bp, curve_point, bnctx);
    }
    int t0 = BN_mul(tmp, ephemeral_key, ctx->pk, bnctx);
    int r1 = BN_mod_add(ctxt2, ptxt, tmp, curve_point, bnctx);
    if (r1 == 0) {
        r1 = BN_mod_add(ctxt2, ptxt, tmp, curve_point, bnctx);
    }
    BN_free(curve_point);
    BN_free(ephemeral_key);
    BN_free(tmp);
}

void ecceg_decrypt(struct ecc_elgamal_ctx * ctx, BIGNUM *ctxt1, BIGNUM *ctxt2, const BIGNUM *ptxt) {
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *curve_point;
    curve_point = BN_new();
    BIGNUM *two;
    two = BN_new();
    BIGNUM *five_two_one;
    five_two_one = BN_new();
    BN_set_word(two, 2);
    BN_set_word(five_two_one, 521);
    BIGNUM *z1;
    z1 = BN_new();
    BN_one(z1);
    BIGNUM *tmp;
    tmp = BN_new();
    int r0 = BN_exp(curve_point, two, five_two_one, bnctx);
    r0 = BN_sub(curve_point, curve_point, z1);
    r0 = BN_mul(tmp, ctxt1, ctx->sk, bnctx);
    r0 = BN_mod_sub(ptxt, ctxt2, tmp, curve_point, bnctx);
    if (r0 == 0) {
        r0 = BN_mod_sub(ptxt, ctxt2, tmp, curve_point, bnctx);
    }
    BN_free(curve_point);
    BN_free(tmp);
}

void pkg_pk(struct ecc_elgamal_ctx * ctx, char * prefix) {
    char *pkfilename[256];
    char *pknum[2];
    char *bpnum[2];
    FILE *pkfile; 
    strcpy(pkfilename, prefix);
    strcat(pkfilename, ".ecc.pk");
    int pkbytes = BN_num_bytes(ctx->pk);
    int bpbytes = BN_num_bytes(ctx->bp);
    sprintf(pknum, "%d", pkbytes);
    sprintf(bpnum, "%d", bpbytes);
    unsigned char *pk[pkbytes];
    unsigned char *bp[bpbytes];
    BN_bn2bin(ctx->pk, pk);
    BN_bn2bin(ctx->bp, bp);
    pkfile = fopen(pkfilename, "wb");
    fwrite(pknum, 1, strlen(pknum), pkfile);
    fwrite(pk, 1, pkbytes, pkfile); 
    fwrite(bpnum, 1, strlen(bpnum), pkfile);
    fwrite(bp, 1, bpbytes, pkfile); 
    fclose(pkfile);
}

void pkg_sk(struct ecc_elgamal_ctx * ctx, char * prefix) {
    char *skfilename[256];
    char *sknum[2];
    FILE *skfile;
    strcpy(skfilename, prefix);
    strcat(skfilename, ".ecc.sk");
    int skbytes = BN_num_bytes(ctx->sk);
    sprintf(sknum, "%d", skbytes);
    unsigned char *sk[skbytes];
    BN_bn2bin(ctx->sk, sk);
    skfile = fopen(skfilename, "wb");
    fwrite(sknum, 1, strlen(sknum), skfile);
    fwrite(sk, 1, skbytes, skfile);
    fclose(skfile);
}

void load_pkfile(char *filename, struct ecc_elgamal_ctx *ctx) {
    int good = 0;
    BIGNUM *z0;
    z0 = BN_new();
    BN_zero(z0);
    int c = 0;
    while (good == 0) {

        ctx->pk = BN_new();
        ctx->bp = BN_new();
        int pksize = 2;
        int bpsize = 2;
        unsigned char *pknum[pksize];
        unsigned char *bpnum[bpsize];
        FILE *keyfile;
        keyfile = fopen(filename, "rb");
        fread(pknum, 1, pksize, keyfile);
        int pkn = atoi(pknum);
        unsigned char pk[pkn];
        fread(pk, 1, pkn, keyfile);
        fread(bpnum, 1, bpsize, keyfile);
        int bpn = atoi(bpnum);
        unsigned char bp[bpn];
        fread(bp, 1, bpn, keyfile);

        fclose(keyfile);
        BN_bin2bn(pk, pkn, ctx->pk);
        BN_bin2bn(bp, bpn, ctx->bp);
        if ((BN_cmp(ctx->pk, z0) != 0) && (BN_cmp(ctx->bp, z0) != 0)) {
            good = 1;
        }
        if (c >= 3) {
            printf("Error: Unable to load public key file\n");
            exit(1);
        }
        c += 1;
    }
}

void load_skfile(char *filename, struct ecc_elgamal_ctx *ctx) {
    int good = 0;
    BIGNUM *z0;
    z0 = BN_new();
    BN_zero(z0);
    int c = 0;
    while (good == 0) {
        BIGNUM *chk;
        chk = BN_new();
        ctx->sk = BN_new();
        int sksize = 2;
        unsigned char *sknum[sksize];
        FILE *keyfile;
        keyfile = fopen(filename, "rb");
        fread(sknum, 1, sksize, keyfile);
        int skn = atoi(sknum);
        unsigned char sk[skn];
        fread(sk, 1, skn, keyfile);
        fclose(keyfile);
        BN_bin2bn(sk, skn, ctx->sk);
        if ((BN_cmp(ctx->sk, z0) != 0)) {
            good = 1;
        }
        if (c >= 3) {
            printf("Error: Unable to load secret key file\n");
            exit(1);
        }
        c += 1;
    }
}

int ecc_keygen(struct ecc_elgamal_ctx *ctx) {
    BN_CTX *bnctx = BN_CTX_new();
    BN_CTX_start(bnctx);
    ctx->pk = BN_new();
    ctx->sk = BN_new();
    ctx->bp = BN_new();
    BIGNUM *z1;
    z1 = BN_new();
    /* Set Z1 to equal 1 */
    BN_one(z1);
    BIGNUM *tmp;
    tmp = BN_new();

    BIGNUM *curve_point;
    curve_point = BN_new();
    BIGNUM *two;
    two = BN_new();
    BIGNUM *five_two_one;
    five_two_one = BN_new();
    BN_set_word(two, 2);
    BN_set_word(five_two_one, 521);
    BIGNUM *curve_point_minus_one;
    curve_point_minus_one = BN_new();
    BIGNUM *base_point_minus_one;
    base_point_minus_one = BN_new();
    int r0 = BN_exp(curve_point, two, five_two_one, bnctx);
    r0 = BN_sub(curve_point, curve_point, z1);
    r0 = BN_sub(curve_point_minus_one, curve_point, z1);
    int randstat = 0;
    while (randstat != 1) {
        unsigned seed[524288];
        FILE *randfile;
        randfile = fopen("/dev/urandom", "rb");
        fread(seed, 1, 524288, randfile);
        fclose(randfile);

        RAND_seed(seed, 524288);
        randstat = RAND_status();
    }
    /* Generate the base point */
    BN_rand_range(ctx->bp, curve_point_minus_one);
    BN_gcd(tmp, ctx->bp, curve_point_minus_one, bnctx);
    while ((BN_cmp(tmp, z1) != 0)) {
        BN_rand_range(ctx->bp, curve_point_minus_one);
        BN_gcd(tmp, ctx->bp, curve_point_minus_one, bnctx);
    }
    BN_sub(base_point_minus_one, ctx->bp, z1);
    /* Generate the private key */
    BN_rand_range(ctx->sk, base_point_minus_one);
    /* Generate the public key */
    BN_mod_mul(ctx->pk, ctx->sk, ctx->bp, curve_point, bnctx);

    BIGNUM *ctxt1;
    BIGNUM *ctxt2;
    BIGNUM *ptxt;
    BIGNUM *msg;
    ctxt1 = BN_new();
    ctxt2 = BN_new();
    ptxt = BN_new();
    msg = BN_new();
    BN_set_word(msg, 123);
    ecceg_encrypt(ctx, ctxt1, ctxt2, msg);
    ecceg_decrypt(ctx, ctxt1, ctxt2, ptxt);
    int good = 1;
    if (BN_cmp(ptxt, msg) == 0) {
        good = 0;
    }
    else {
        printf("Error: ECC El Gamal keys failed to generate.\n");
        exit(2);
    }
    BN_free(curve_point);
    BN_free(curve_point_minus_one);
    BN_free(base_point_minus_one);
    BN_free(msg);
    BN_free(ctxt1);
    BN_free(ctxt2);
    BN_free(ptxt);
    BN_free(tmp);
    BN_free(z1);
    return good;
}
