/* ChaCha */
/* Implementation by KryptoMagick (Karl Zander) */
/* 256 bit key / 512 bit state / 64 bit nonce */
/* 512 bit output block */
/* 20 rounds */

uint32_t chacha_C0[4] = {0x65787061, 0x6e642033, 0x322d6279, 0x7465206b};

struct chacha_state {
    uint32_t S[16];
    uint32_t O[16];
    int rounds;
};

uint32_t chacha_rotl(uint32_t a, int b) {
    return ((a << b) | (a >> (32 - b)));
}

void chacha_qtr_rnd(struct chacha_state *state, int a, int b, int c, int d) {
    state->S[a] += state->S[b];
    state->S[d] = chacha_rotl(state->S[d] ^ state->S[a], 16);
    state->S[c] += state->S[d];
    state->S[b] = chacha_rotl(state->S[b] ^ state->S[c], 12);
    state->S[a] += state->S[b];
    state->S[d] = chacha_rotl(state->S[d] ^ state->S[a], 8);
    state->S[c] += state->S[d];
    state->S[b] = chacha_rotl(state->S[b] ^ state->S[c], 7);
}

void chacha_update(struct chacha_state *state) {
    memcpy(state->O, state->S, 16*sizeof(uint32_t));
    for (int i = 0; i < state->rounds; i++) {
        chacha_qtr_rnd(state, 0, 4, 8, 12);
        chacha_qtr_rnd(state, 1, 5, 9, 13);
        chacha_qtr_rnd(state, 2, 6, 10, 14);
        chacha_qtr_rnd(state, 3, 7, 11, 15);
        chacha_qtr_rnd(state, 0, 5, 10, 15);
        chacha_qtr_rnd(state, 1, 6, 11, 12);
        chacha_qtr_rnd(state, 2, 7, 8, 13);
        chacha_qtr_rnd(state, 3, 4, 9, 14);
    }
    state->S[12] += 1;

    state->O[0] += state->S[0];
    state->O[1] += state->S[1];
    state->O[2] += state->S[2];
    state->O[3] += state->S[3];
    state->O[4] += state->S[4];
    state->O[5] += state->S[5];
    state->O[6] += state->S[6];
    state->O[7] += state->S[7];
    state->O[8] += state->S[8];
    state->O[9] += state->S[9];
    state->O[10] += state->S[10];
    state->O[11] += state->S[11];
    state->O[12] += state->S[12];
    state->O[13] += state->S[13];
    state->O[14] += state->S[14];
    state->O[15] += state->S[15];
}

void chacha_keysetup(struct chacha_state *state, uint8_t *key, uint8_t *nonce) {
    state->rounds = 20;
    state->S[0] = chacha_C0[0];
    state->S[1] = chacha_C0[1];
    state->S[2] = chacha_C0[2];
    state->S[3] = chacha_C0[3];
    state->S[4] = ((uint32_t)(key[0]) << 24) + ((uint32_t)key[1] << 16) + ((uint32_t)key[2] << 8) + ((uint32_t)key[3]);
    state->S[5] = ((uint32_t)(key[4]) << 24) + ((uint32_t)key[5] << 16) + ((uint32_t)key[6] << 8) + ((uint32_t)key[7]);
    state->S[6] = ((uint32_t)(key[8]) << 24) + ((uint32_t)key[9] << 16) + ((uint32_t)key[10] << 8) + ((uint32_t)key[11]);
    state->S[7] = ((uint32_t)(key[12]) << 24) + ((uint32_t)key[13] << 16) + ((uint32_t)key[14] << 8) + ((uint32_t)key[15]);
    state->S[8] = ((uint32_t)(key[16]) << 24) + ((uint32_t)key[17] << 16) + ((uint32_t)key[18] << 8) + ((uint32_t)key[19]);
    state->S[9] = ((uint32_t)(key[20]) << 24) + ((uint32_t)key[21] << 16) + ((uint32_t)key[22] << 8) + ((uint32_t)key[23]);
    state->S[10] = ((uint32_t)(key[24]) << 24) + ((uint32_t)key[25] << 16) + ((uint32_t)key[26] << 8) + ((uint32_t)key[27]);
    state->S[11] = ((uint32_t)(key[28]) << 24) + ((uint32_t)key[29] << 16) + ((uint32_t)key[30] << 8) + ((uint32_t)key[31]);

    state->S[12] = 0;
    state->S[13] = 0;

    state->S[14] = ((uint32_t)(nonce[0]) << 24) + ((uint32_t)nonce[1] << 16) + ((uint32_t)nonce[2] << 8) + ((uint32_t)nonce[3]);
    state->S[15] = ((uint32_t)(nonce[4]) << 24) + ((uint32_t)nonce[5] << 16) + ((uint32_t)nonce[6] << 8) + ((uint32_t)nonce[7]);

}

void chacha_xor_block(struct chacha_state *state, uint8_t *block) {
    block[0] ^= (state->O[0] & 0xFF000000) >> 24;
    block[1] ^= (state->O[0] & 0x00FF0000) >> 16;
    block[2] ^= (state->O[0] & 0x0000FF00) >> 8;
    block[3] ^= (state->O[0] & 0x000000FF);
    block[4] ^= (state->O[1] & 0xFF000000) >> 24;
    block[5] ^= (state->O[1] & 0x00FF0000) >> 16;
    block[6] ^= (state->O[1] & 0x0000FF00) >> 8;
    block[7] ^= (state->O[1] & 0x000000FF);
    block[8] ^= (state->O[2] & 0xFF000000) >> 24;
    block[9] ^= (state->O[2] & 0x00FF0000) >> 16;
    block[10] ^= (state->O[2] & 0x0000FF00) >> 8;
    block[11] ^= (state->O[2] & 0x000000FF);
    block[12] ^= (state->O[3] & 0xFF000000) >> 24;
    block[13] ^= (state->O[3] & 0x00FF0000) >> 16;
    block[14] ^= (state->O[3] & 0x0000FF00) >> 8;
    block[15] ^= (state->O[3] & 0x000000FF);
    block[16] ^= (state->O[4] & 0xFF000000) >> 24;
    block[17] ^= (state->O[4] & 0x00FF0000) >> 16;
    block[18] ^= (state->O[4] & 0x0000FF00) >> 8;
    block[19] ^= (state->O[4] & 0x000000FF);
    block[20] ^= (state->O[5] & 0xFF000000) >> 24;
    block[21] ^= (state->O[5] & 0x00FF0000) >> 16;
    block[22] ^= (state->O[5] & 0x0000FF00) >> 8;
    block[23] ^= (state->O[5] & 0x000000FF);
    block[24] ^= (state->O[6] & 0xFF000000) >> 24;
    block[25] ^= (state->O[6] & 0x00FF0000) >> 16;
    block[26] ^= (state->O[6] & 0x0000FF00) >> 8;
    block[27] ^= (state->O[6] & 0x000000FF);
    block[28] ^= (state->O[7] & 0xFF000000) >> 24;
    block[29] ^= (state->O[7] & 0x00FF0000) >> 16;
    block[30] ^= (state->O[7] & 0x0000FF00) >> 8;
    block[31] ^= (state->S[7] & 0x000000FF);
    block[32] ^= (state->O[8] & 0xFF000000) >> 24;
    block[33] ^= (state->O[8] & 0x00FF0000) >> 16;
    block[34] ^= (state->O[8] & 0x0000FF00) >> 8;
    block[35] ^= (state->O[8] & 0x000000FF);
    block[36] ^= (state->S[9] & 0xFF000000) >> 24;
    block[37] ^= (state->O[9] & 0x00FF0000) >> 16;
    block[38] ^= (state->O[9] & 0x0000FF00) >> 8;
    block[39] ^= (state->O[9] & 0x000000FF);
    block[40] ^= (state->O[10] & 0xFF000000) >> 24;
    block[41] ^= (state->O[10] & 0x00FF0000) >> 16;
    block[42] ^= (state->O[10] & 0x0000FF00) >> 8;
    block[43] ^= (state->O[10] & 0x000000FF);
    block[44] ^= (state->O[11] & 0xFF000000) >> 24;
    block[45] ^= (state->O[11] & 0x00FF0000) >> 16;
    block[46] ^= (state->O[11] & 0x0000FF00) >> 8;
    block[47] ^= (state->O[11] & 0x000000FF);
    block[48] ^= (state->O[12] & 0xFF000000) >> 24;
    block[49] ^= (state->O[12] & 0x00FF0000) >> 16;
    block[50] ^= (state->O[12] & 0x0000FF00) >> 8;
    block[51] ^= (state->O[12] & 0x000000FF);
    block[52] ^= (state->O[13] & 0xFF000000) >> 24;
    block[53] ^= (state->O[13] & 0x00FF0000) >> 16;
    block[54] ^= (state->O[13] & 0x0000FF00) >> 8;
    block[55] ^= (state->O[13] & 0x000000FF);
    block[56] ^= (state->O[14] & 0xFF000000) >> 24;
    block[57] ^= (state->O[14] & 0x00FF0000) >> 16;
    block[58] ^= (state->O[14] & 0x0000FF00) >> 8;
    block[59] ^= (state->O[14] & 0x000000FF);
    block[60] ^= (state->O[15] & 0xFF000000) >> 24;
    block[61] ^= (state->O[15] & 0x00FF0000) >> 16;
    block[62] ^= (state->O[15] & 0x0000FF00) >> 8;
    block[63] ^= (state->O[15] & 0x000000FF);
}

void chacha_encrypt(char *inputfile, char *outputfile, char *pkfile) {
    struct ecc_elgamal_ctx ctx;
    load_pkfile(pkfile, &ctx);
    uint8_t key[32];
    urandom(key, 32); 
    BIGNUM *bn_keyptxt;
    BIGNUM *bn_keyctxt1;
    BIGNUM *bn_keyctxt2;
    bn_keyptxt = BN_new();
    bn_keyctxt1 = BN_new();
    bn_keyctxt2 = BN_new(); 
    BN_bin2bn(key, 32, bn_keyptxt);
    ecceg_encrypt(&ctx, bn_keyctxt1, bn_keyctxt2, bn_keyptxt);
    int ctxt1bytes = BN_num_bytes(bn_keyctxt1);
    int ctxt2bytes = BN_num_bytes(bn_keyctxt2);
    uint8_t keyctxt1[ctxt1bytes];
    uint8_t keyctxt2[ctxt2bytes];
    char *ctxt1num[2];
    char *ctxt2num[2];
    sprintf(ctxt1num, "%d", ctxt1bytes);
    sprintf(ctxt2num, "%d", ctxt2bytes);
    BN_bn2bin(bn_keyctxt1, keyctxt1);
    BN_bn2bin(bn_keyctxt2, keyctxt2);

    struct chacha_state state;
    int blocklen = 64;
    int bufsize = 64;
    uint8_t nonce[8];
    urandom(nonce, 8);
    chacha_keysetup(&state, key, nonce);
    FILE *infile, *outfile;
    infile = fopen(inputfile, "rb");
    outfile = fopen(outputfile, "wb");
    fwrite(ctxt1num, 1, 2, outfile);
    fwrite(keyctxt1, 1, ctxt1bytes, outfile);
    fwrite(ctxt2num, 1, 2, outfile);
    fwrite(keyctxt2, 1, ctxt2bytes, outfile);
    fwrite(nonce, 1, 8, outfile);
    fseek(infile, 0, SEEK_END);
    uint32_t datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    uint32_t blocks = datalen / blocklen;
    int extra = datalen % blocklen;
    int extrabytes = blocklen - (datalen % blocklen);
    if (extra != 0) {
       blocks += 1;
    }
    for (uint32_t b = 0; b < blocks; b++) {
        uint8_t block[64];
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(block, 1, bufsize, infile);
        chacha_update(&state);
        chacha_xor_block(&state, block);
        fwrite(block, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
    uint8_t kdf_key[32];
    qx_kdf(key, 32, kdf_key, 10000);
    qx_hmac_file_write(outputfile, kdf_key);
}

void chacha_decrypt(char *inputfile, char *outputfile, char *skfile) {
    struct ecc_elgamal_ctx ctx;
    load_skfile(skfile, &ctx);
    uint8_t key[32];

    struct chacha_state state;
    int blocklen = 64;
    int bufsize = 64;
    uint8_t nonce[8];
    FILE *infile, *outfile;
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    uint32_t datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    char *ctxt1num[2];
    fread(ctxt1num, 1, 2, infile);
    int ctxt1n = atoi(ctxt1num);
    uint8_t keyctxt1[ctxt1n];
    fread(keyctxt1, 1, ctxt1n, infile);
    char *ctxt2num[2];
    fread(ctxt2num, 1, 2, infile);
    int ctxt2n = atoi(ctxt2num);
    uint8_t keyctxt2[ctxt2n];
    fread(keyctxt2, 1, ctxt2n, infile);
    fread(nonce, 1, 8, infile);
    datalen = datalen - 8 - ctxt1n - ctxt2n - 32 - 2 - 2;
    uint32_t blocks = datalen / blocklen;
    int extra = datalen % blocklen;
    if (extra != 0) {
       blocks += 1;
    }

    BIGNUM *bn_keyptxt;
    BIGNUM *bn_keyctxt1;
    BIGNUM *bn_keyctxt2;
    bn_keyptxt = BN_new();
    bn_keyctxt1 = BN_new();
    bn_keyctxt2 = BN_new();
    BN_bin2bn(keyctxt1, ctxt1n, bn_keyctxt1);
    BN_bin2bn(keyctxt2, ctxt2n, bn_keyctxt2);
    ecceg_decrypt(&ctx, bn_keyctxt1, bn_keyctxt2, bn_keyptxt);
    BN_bn2bin(bn_keyptxt, key);
    fclose(infile);

    uint8_t kdf_key[32];
    qx_kdf(key, 32, kdf_key, 10000);
    if (qx_hmac_file_read_verify_offset(inputfile, kdf_key, (0)) == -1) {
        printf("Error: QX HMAC message is not authentic.\n");
        exit(2);
    }
    infile = fopen(inputfile, "rb");
    outfile = fopen(outputfile, "wb");
    fseek(infile, (8 + ctxt1n + ctxt2n + 2 + 2), SEEK_SET);
    chacha_keysetup(&state, key, nonce);

    for (uint32_t b = 0; b < blocks; b++) {
        uint8_t block[64];
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(block, 1, bufsize, infile);
        chacha_update(&state);
        chacha_xor_block(&state, block);
        fwrite(block, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
}
