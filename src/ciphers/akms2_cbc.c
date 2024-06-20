/* Advanced KryptoMagick Standard 2 (AKMS2) */
/* by KryptoMagick (Karl Zander) */
/* 256 bit key / 128 bit block size */
/* 64 rounds */

uint32_t akms2_C0[4] = {0xb5232c67, 0xabdd2f50, 0xab790aaa, 0xe8395ac0};

struct akms2_state {
    uint32_t S[4];
    uint32_t T[4];
    uint32_t K[64][4];
    uint32_t last[4];
    uint32_t next[4];
    int rounds;
};

uint32_t akms2_rotl(uint32_t a, int b) {
    return ((a << b) | (a >> (32 - b)));
}

uint32_t akms2_rotr(uint32_t a, int b) {
    return ((a >> b) | (a << (32 - b)));
}

void akms2_ksa(struct akms2_state *state, uint8_t *key) {
    state->rounds = 64;

    state->K[0][0] = ((key[0] << 24) + (key[1] << 16) + (key[2] << 8) + key[3]);
    state->K[0][1] = ((key[4] << 24) + (key[5] << 16) + (key[6] << 8) + key[7]);
    state->K[0][2] = ((key[8] << 24) + (key[9] << 16) + (key[10] << 8) + key[11]);
    state->K[0][3] = ((key[12] << 24) + (key[13] << 16) + (key[14] << 8) + key[15]);
    state->K[63][0] = ((key[16] << 24) + (key[17] << 16) + (key[18] << 8) + key[19]);
    state->K[63][1] = ((key[20] << 24) + (key[21] << 16) + (key[22] << 8) + key[23]);
    state->K[63][2] = ((key[24] << 24) + (key[25] << 16) + (key[26] << 8) + key[27]);
    state->K[63][3] = ((key[28] << 24) + (key[29] << 16) + (key[30] << 8) + key[31]);

    state->S[0] = state->K[0][0] + akms2_C0[0];
    state->S[1] = state->K[0][1] + akms2_C0[1];
    state->S[2] = state->K[0][2] + akms2_C0[2];
    state->S[3] = state->K[0][3] + akms2_C0[3];

    state->T[0] = state->K[63][0];
    state->T[1] = state->K[63][1];
    state->T[2] = state->K[63][2];
    state->T[3] = state->K[63][3];

    int i = 0;
    for (int r = 1; r < state->rounds - 1; r++) {
        state->S[i & 0x03] ^= akms2_rotl(state->T[i & 0x03], 6) + akms2_rotl(state->S[(i + 3) & 0x03], 5);
        state->S[(i + 1) & 0x03] ^= akms2_rotl(state->T[(i + 1) & 0x03], 10) + akms2_rotl(state->S[(i + 2) & 0x03], 9);
        state->S[(i + 2) & 0x03] ^= akms2_rotl(state->T[(i + 2) & 0x03], 7) + akms2_rotl(state->S[i & 0x03], 6);
        state->S[(i + 3) & 0x03] ^= akms2_rotl(state->T[(i + 3) & 0x03], 12) + akms2_rotl(state->S[(i + 1) & 0x03], 11);

        state->T[i & 0x03] ^= akms2_rotl(state->S[i & 0x03], 6) + akms2_rotl(state->T[(i + 3) & 0x03], 5);
        state->T[(i + 1) & 0x03] ^= akms2_rotl(state->S[(i + 1) & 0x03], 10) + akms2_rotl(state->T[i & 0x03], 9);
        state->T[(i + 2) & 0x03] ^= akms2_rotl(state->S[(i + 2) & 0x03], 7) + akms2_rotl(state->T[(i + 1) & 0x03], 6);
        state->T[(i + 3) & 0x03] ^= akms2_rotl(state->S[(i + 3) & 0x03], 12) + akms2_rotl(state->T[(i + 2) & 0x03], 11);

        state->K[r][0] = state->S[0];
        state->K[r][1] = state->S[1];
        state->K[r][2] = state->S[2];
        state->K[r][3] = state->S[3];
        i += 1;
    }
}

void akms2_encrypt_block(struct akms2_state *state) {
    for (int r = 0; r < state->rounds; r++) {
        state->S[1] += state->S[2];
        state->S[1] = akms2_rotl(state->S[1], 5);
        state->S[1] ^= state->S[0];
        state->S[1] ^= state->K[r][1];
        state->S[2] += state->S[1];
        state->S[2] = akms2_rotl(state->S[2], 9);
        state->S[2] ^= state->S[3];
        state->S[2] ^= state->K[r][2];
        state->S[0] += state->S[2];
        state->S[0] = akms2_rotr(state->S[0], 6);
        state->S[0] ^= state->S[3];
        state->S[0] ^= state->K[r][0];
        state->S[3] += state->S[0];
        state->S[3] = akms2_rotr(state->S[3], 11);
        state->S[3] ^= state->S[1];
        state->S[3] ^= state->K[r][3];
    }
}

void akms2_decrypt_block(struct akms2_state *state) {
    for (int r = state->rounds - 1; r != -1; r--) {
        state->S[3] ^= state->K[r][3];
        state->S[3] ^= state->S[1];
        state->S[3] = akms2_rotl(state->S[3], 11);
        state->S[3] -= state->S[0];
        state->S[0] ^= state->K[r][0];
        state->S[0] ^= state->S[3];
        state->S[0] = akms2_rotl(state->S[0], 6);
        state->S[0] -= state->S[2];
        state->S[2] ^= state->K[r][2];
        state->S[2] ^= state->S[3];
        state->S[2] = akms2_rotr(state->S[2], 9);
        state->S[2] -= state->S[1];
        state->S[1] ^= state->K[r][1];
        state->S[1] ^= state->S[0];
        state->S[1] = akms2_rotr(state->S[1], 5);
        state->S[1] -= state->S[2];
    }
}

void akms2_load_block(struct akms2_state *state, uint8_t *block) {
    state->S[0] = ((block[0] << 24) + (block[1] << 16) + (block[2] << 8) + block[3]);
    state->S[1] = ((block[4] << 24) + (block[5] << 16) + (block[6] << 8) + block[7]);
    state->S[2] = ((block[8] << 24) + (block[9] << 16) + (block[10] << 8) + block[11]);
    state->S[3] = ((block[12] << 24) + (block[13] << 16) + (block[14] << 8) + block[15]);
}

void akms2_unload_block(struct akms2_state *state, uint8_t *block) {
    block[0] = state->S[0] >> 24;
    block[1] = state->S[0] >> 16;
    block[2] = state->S[0] >> 8;
    block[3] = state->S[0];
    block[4] = state->S[1] >> 24;
    block[5] = state->S[1] >> 16;
    block[6] = state->S[1] >> 8;
    block[7] = state->S[1];
    block[8] = state->S[2] >> 24;
    block[9] = state->S[2] >> 16;
    block[10] = state->S[2] >> 8;
    block[11] = state->S[2];
    block[12] = state->S[3] >> 24;
    block[13] = state->S[3] >> 16;
    block[14] = state->S[3] >> 8;
    block[15] = state->S[3];
}

void akms2_load_iv(struct akms2_state *state, uint8_t *iv) {
    state->last[0] = ((iv[0] << 24) + (iv[1] << 16) + (iv[2] << 8) + iv[3]);
    state->last[1] = ((iv[4] << 24) + (iv[5] << 16) + (iv[6] << 8) + iv[7]);
    state->last[2] = ((iv[8] << 24) + (iv[9] << 16) + (iv[10] << 8) + iv[11]);
    state->last[3] = ((iv[12] << 24) + (iv[13] << 16) + (iv[14] << 8) + iv[15]);
}

void akms2_cbc_last(struct akms2_state *state) {
    state->S[0] ^= state->last[0];
    state->S[1] ^= state->last[1];
    state->S[2] ^= state->last[2];
    state->S[3] ^= state->last[3];
}

void akms2_cbc_next(struct akms2_state *state) {
    state->last[0] = state->S[0];
    state->last[1] = state->S[1];
    state->last[2] = state->S[2];
    state->last[3] = state->S[3];
}

void akms2_cbc_next_inv(struct akms2_state *state) {
    state->next[0] = state->S[0];
    state->next[1] = state->S[1];
    state->next[2] = state->S[2];
    state->next[3] = state->S[3];
}

void akms2_cbc_last_inv(struct akms2_state *state) {
    state->last[0] = state->next[0];
    state->last[1] = state->next[1];
    state->last[2] = state->next[2];
    state->last[3] = state->next[3];
}

void akms2_cbc_encrypt(char *inputfile, char *outputfile, char *pkfile) {
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

    struct akms2_state state;
    akms2_ksa(&state, key);
    int blocklen = 16;
    int bufsize = 16;
    uint8_t iv[blocklen];
    urandom(iv, blocklen);
    akms2_load_iv(&state, iv);
    FILE *infile, *outfile;
    infile = fopen(inputfile, "rb");
    outfile = fopen(outputfile, "wb");
    fwrite(ctxt1num, 1, 2, outfile);
    fwrite(keyctxt1, 1, ctxt1bytes, outfile);
    fwrite(ctxt2num, 1, 2, outfile);
    fwrite(keyctxt2, 1, ctxt2bytes, outfile);
    fwrite(iv, 1, blocklen, outfile);
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
        uint8_t block[16];
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
            for (int p = 0; p < extrabytes; p++) {
                block[(blocklen-1-p)] = (uint8_t)extrabytes;
            }
        }
        fread(block, 1, bufsize, infile);
        akms2_load_block(&state, block);
        akms2_cbc_last(&state);
        akms2_encrypt_block(&state);
        akms2_cbc_next(&state);
        akms2_unload_block(&state, block);
        fwrite(block, 1, blocklen, outfile);
    }
    fclose(infile);
    fclose(outfile);
    uint8_t kdf_key[32];
    qx_kdf(key, 32, kdf_key, 10000);
    qx_hmac_file_write(outputfile, kdf_key);
}

void akms2_cbc_decrypt(char *inputfile, char *outputfile, char *skfile) {
    struct ecc_elgamal_ctx ctx;
    load_skfile(skfile, &ctx);
    uint8_t key[32];

    struct akms2_state state;
    int blocklen = 16;
    uint8_t iv[blocklen];
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
    fread(iv, 1, blocklen, infile);
    akms2_load_iv(&state, iv);
    datalen = datalen - blocklen - ctxt1n - ctxt2n - 32 - 2 - 2;
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
    fseek(infile, (blocklen + ctxt1n + ctxt2n + 2 + 2), SEEK_SET);
    akms2_ksa(&state, key);

    for (uint32_t b = 0; b < blocks; b++) {
        uint8_t block[16];
        fread(block, 1, blocklen, infile);
        akms2_load_block(&state, block);
        akms2_cbc_next_inv(&state);
        akms2_decrypt_block(&state);
        akms2_cbc_last(&state);
        akms2_cbc_last_inv(&state);
        akms2_unload_block(&state, block);

        if (b == (blocks - 1)) {
            int padcheck = block[blocklen - 1];
            int g = blocklen - 1;
            int count = 0;
            for (int p = 0; p < padcheck; p++) {
                if ((int)block[g] == padcheck) {
                    count += 1;
                }
                g = g - 1;
            }
            if (padcheck == count) {
                blocklen = blocklen - count;
            }
        }
        fwrite(block, 1, blocklen, outfile);
    }
    fclose(infile);
    fclose(outfile);
}
