/* Advanced Encryption Standard (AES) */
/* Rijdael Block Cipher */
/* Implementation by KryptoMagick (Karl Zander) */
/* 256 bit key / 128 bit block size */
/* 14 rounds */

/* FIPS-197 and the Design of Rijdael used as reference */
/* Validated against NIST test vectors */

uint8_t aes_S0[256] = {99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22};

uint8_t aes_S0i[256] = {82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125};

uint8_t aes_RC[8] = {0, 1, 2, 4, 8, 16, 32, 64};

struct aes_state {
    uint8_t S[4][4];
    uint8_t T[4][4];
    uint8_t K[15][4][4];
    uint8_t last[4][4];
    uint8_t next[4][4];
    int rounds;
};

uint8_t xtime(uint8_t a){
    return ((a << 1) ^ (((a >> 7) & 1) * 27));
}

uint8_t mul(uint8_t a, uint8_t b){
    return ((b & 1) * a) ^ ((b >> 1 & 1) * xtime(a)) ^ ((b >> 2 & 1) * xtime(xtime(a))) ^ ((b >> 3 & 1) * xtime(xtime(xtime(a)))) ^ ((b >> 4 & 1) * xtime(xtime(xtime(xtime(a))))) ^ ((b >> 5 & 1) * xtime(xtime(xtime(xtime(xtime(a)))))) ^ ((b >> 6 & 1) * xtime(xtime(xtime(xtime(xtime(xtime(a))))))) ^ ((b >> 7 & 1) * xtime(xtime(xtime(xtime(xtime(xtime(xtime(a))))))));
}

void aes_sub_bytes(struct aes_state *state) {
    state->S[0][0] = aes_S0[state->S[0][0]];
    state->S[0][1] = aes_S0[state->S[0][1]];
    state->S[0][2] = aes_S0[state->S[0][2]];
    state->S[0][3] = aes_S0[state->S[0][3]];
    state->S[1][0] = aes_S0[state->S[1][0]];
    state->S[1][1] = aes_S0[state->S[1][1]];
    state->S[1][2] = aes_S0[state->S[1][2]];
    state->S[1][3] = aes_S0[state->S[1][3]];
    state->S[2][0] = aes_S0[state->S[2][0]];
    state->S[2][1] = aes_S0[state->S[2][1]];
    state->S[2][2] = aes_S0[state->S[2][2]];
    state->S[2][3] = aes_S0[state->S[2][3]];
    state->S[3][0] = aes_S0[state->S[3][0]];
    state->S[3][1] = aes_S0[state->S[3][1]];
    state->S[3][2] = aes_S0[state->S[3][2]];
    state->S[3][3] = aes_S0[state->S[3][3]];
}

void aes_sub_bytes_inv(struct aes_state *state) {
    state->S[0][0] = aes_S0i[state->S[0][0]];
    state->S[0][1] = aes_S0i[state->S[0][1]];
    state->S[0][2] = aes_S0i[state->S[0][2]];
    state->S[0][3] = aes_S0i[state->S[0][3]];
    state->S[1][0] = aes_S0i[state->S[1][0]];
    state->S[1][1] = aes_S0i[state->S[1][1]];
    state->S[1][2] = aes_S0i[state->S[1][2]];
    state->S[1][3] = aes_S0i[state->S[1][3]];
    state->S[2][0] = aes_S0i[state->S[2][0]];
    state->S[2][1] = aes_S0i[state->S[2][1]]; 
    state->S[2][2] = aes_S0i[state->S[2][2]];
    state->S[2][3] = aes_S0i[state->S[2][3]];
    state->S[3][0] = aes_S0i[state->S[3][0]];
    state->S[3][1] = aes_S0i[state->S[3][1]];
    state->S[3][2] = aes_S0i[state->S[3][2]];
    state->S[3][3] = aes_S0i[state->S[3][3]];
}

void aes_shift_rows(struct aes_state *state) {
    state->T[0][0] = state->S[0][0];
    state->T[0][1] = state->S[0][1];
    state->T[0][2] = state->S[0][2];
    state->T[0][3] = state->S[0][3];
    state->T[1][0] = state->S[1][0];
    state->T[1][1] = state->S[1][1];
    state->T[1][2] = state->S[1][2];
    state->T[1][3] = state->S[1][3];
    state->T[2][0] = state->S[2][0];
    state->T[2][1] = state->S[2][1];
    state->T[2][2] = state->S[2][2];
    state->T[2][3] = state->S[2][3];
    state->T[3][0] = state->S[3][0];
    state->T[3][1] = state->S[3][1];
    state->T[3][2] = state->S[3][2];
    state->T[3][3] = state->S[3][3];

    state->S[0][0] = state->T[0][0];
    state->S[0][1] = state->T[1][1];
    state->S[0][2] = state->T[2][2];
    state->S[0][3] = state->T[3][3];
    state->S[1][0] = state->T[1][0];
    state->S[1][1] = state->T[2][1];
    state->S[1][2] = state->T[3][2];
    state->S[1][3] = state->T[0][3];
    state->S[2][0] = state->T[2][0];
    state->S[2][1] = state->T[3][1];
    state->S[2][2] = state->T[0][2];
    state->S[2][3] = state->T[1][3];
    state->S[3][0] = state->T[3][0];
    state->S[3][1] = state->T[0][1];
    state->S[3][2] = state->T[1][2];
    state->S[3][3] = state->T[2][3];
}

void aes_shift_rows_inv(struct aes_state *state) {
    state->T[0][0] = state->S[0][0];
    state->T[0][1] = state->S[0][1];
    state->T[0][2] = state->S[0][2];
    state->T[0][3] = state->S[0][3];
    state->T[1][0] = state->S[1][0];
    state->T[1][1] = state->S[1][1];
    state->T[1][2] = state->S[1][2];
    state->T[1][3] = state->S[1][3];
    state->T[2][0] = state->S[2][0];
    state->T[2][1] = state->S[2][1];
    state->T[2][2] = state->S[2][2];
    state->T[2][3] = state->S[2][3];
    state->T[3][0] = state->S[3][0];
    state->T[3][1] = state->S[3][1];
    state->T[3][2] = state->S[3][2];
    state->T[3][3] = state->S[3][3];

    state->S[0][0] = state->T[0][0];
    state->S[0][1] = state->T[3][1];
    state->S[0][2] = state->T[2][2];
    state->S[0][3] = state->T[1][3];
    state->S[1][0] = state->T[1][0];
    state->S[1][1] = state->T[0][1];
    state->S[1][2] = state->T[3][2];
    state->S[1][3] = state->T[2][3];
    state->S[2][0] = state->T[2][0];
    state->S[2][1] = state->T[1][1];
    state->S[2][2] = state->T[0][2];
    state->S[2][3] = state->T[3][3];
    state->S[3][0] = state->T[3][0];
    state->S[3][1] = state->T[2][1];
    state->S[3][2] = state->T[1][2];
    state->S[3][3] = state->T[0][3];
}

void aes_mix_columns(struct aes_state *state) {
    state->T[0][0] = mul(2, state->S[0][0]) ^ mul(3, state->S[0][1]) ^ state->S[0][2] ^ state->S[0][3];
    state->T[0][1] = mul(2, state->S[0][1]) ^ mul(3, state->S[0][2]) ^ state->S[0][3] ^ state->S[0][0];
    state->T[0][2] = mul(2, state->S[0][2]) ^ mul(3, state->S[0][3]) ^ state->S[0][0] ^ state->S[0][1];
    state->T[0][3] = mul(2, state->S[0][3]) ^ mul(3, state->S[0][0]) ^ state->S[0][1] ^ state->S[0][2];

    state->T[1][0] = mul(2, state->S[1][0]) ^ mul(3, state->S[1][1]) ^ state->S[1][2] ^ state->S[1][3];
    state->T[1][1] = mul(2, state->S[1][1]) ^ mul(3, state->S[1][2]) ^ state->S[1][3] ^ state->S[1][0];
    state->T[1][2] = mul(2, state->S[1][2]) ^ mul(3, state->S[1][3]) ^ state->S[1][0] ^ state->S[1][1];
    state->T[1][3] = mul(2, state->S[1][3]) ^ mul(3, state->S[1][0]) ^ state->S[1][1] ^ state->S[1][2];

    state->T[2][0] = mul(2, state->S[2][0]) ^ mul(3, state->S[2][1]) ^ state->S[2][2] ^ state->S[2][3];
    state->T[2][1] = mul(2, state->S[2][1]) ^ mul(3, state->S[2][2]) ^ state->S[2][3] ^ state->S[2][0];
    state->T[2][2] = mul(2, state->S[2][2]) ^ mul(3, state->S[2][3]) ^ state->S[2][0] ^ state->S[2][1];
    state->T[2][3] = mul(2, state->S[2][3]) ^ mul(3, state->S[2][0]) ^ state->S[2][1] ^ state->S[2][2];

    state->T[3][0] = mul(2, state->S[3][0]) ^ mul(3, state->S[3][1]) ^ state->S[3][2] ^ state->S[3][3];
    state->T[3][1] = mul(2, state->S[3][1]) ^ mul(3, state->S[3][2]) ^ state->S[3][3] ^ state->S[3][0];
    state->T[3][2] = mul(2, state->S[3][2]) ^ mul(3, state->S[3][3]) ^ state->S[3][0] ^ state->S[3][1];
    state->T[3][3] = mul(2, state->S[3][3]) ^ mul(3, state->S[3][0]) ^ state->S[3][1] ^ state->S[3][2];

    state->S[0][0] = state->T[0][0];
    state->S[0][1] = state->T[0][1];
    state->S[0][2] = state->T[0][2];
    state->S[0][3] = state->T[0][3];
    state->S[1][0] = state->T[1][0];
    state->S[1][1] = state->T[1][1];
    state->S[1][2] = state->T[1][2];
    state->S[1][3] = state->T[1][3];
    state->S[2][0] = state->T[2][0];
    state->S[2][1] = state->T[2][1];
    state->S[2][2] = state->T[2][2];
    state->S[2][3] = state->T[2][3];
    state->S[3][0] = state->T[3][0];
    state->S[3][1] = state->T[3][1];
    state->S[3][2] = state->T[3][2];
    state->S[3][3] = state->T[3][3];
}

void aes_mix_columns_inv(struct aes_state *state) {
    state->T[0][0] = mul(14, state->S[0][0]) ^ mul(11, state->S[0][1]) ^ mul(13, state->S[0][2]) ^ mul(9, state->S[0][3]);
    state->T[0][1] = mul(14, state->S[0][1]) ^ mul(11, state->S[0][2]) ^ mul(13, state->S[0][3]) ^ mul(9, state->S[0][0]);
    state->T[0][2] = mul(14, state->S[0][2]) ^ mul(11, state->S[0][3]) ^ mul(13, state->S[0][0]) ^ mul(9, state->S[0][1]);
    state->T[0][3] = mul(14, state->S[0][3]) ^ mul(11, state->S[0][0]) ^ mul(13, state->S[0][1]) ^ mul(9, state->S[0][2]);

    state->T[1][0] = mul(9, state->S[1][3]) ^ mul(14, state->S[1][0]) ^ mul(11, state->S[1][1]) ^ mul(13, state->S[1][2]);
    state->T[1][1] = mul(9, state->S[1][0]) ^ mul(14, state->S[1][1]) ^ mul(11, state->S[1][2]) ^ mul(13, state->S[1][3]);
    state->T[1][2] = mul(9, state->S[1][1]) ^ mul(14, state->S[1][2]) ^ mul(11, state->S[1][3]) ^ mul(13, state->S[1][0]);
    state->T[1][3] = mul(9, state->S[1][2]) ^ mul(14, state->S[1][3]) ^ mul(11, state->S[1][0]) ^ mul(13, state->S[1][1]);

    state->T[2][0] = mul(13, state->S[2][2]) ^ mul(9, state->S[2][3]) ^ mul(14, state->S[2][0]) ^ mul(11, state->S[2][1]);
    state->T[2][1] = mul(13, state->S[2][3]) ^ mul(9, state->S[2][0]) ^ mul(14, state->S[2][1]) ^ mul(11, state->S[2][2]);
    state->T[2][2] = mul(13, state->S[2][0]) ^ mul(9, state->S[2][1]) ^ mul(14, state->S[2][2]) ^ mul(11, state->S[2][3]);
    state->T[2][3] = mul(13, state->S[2][1]) ^ mul(9, state->S[2][2]) ^ mul(14, state->S[2][3]) ^ mul(11, state->S[2][0]);

    state->T[3][0] = mul(11, state->S[3][1]) ^ mul(13, state->S[3][2]) ^ mul(9, state->S[3][3]) ^ mul(14, state->S[3][0]);
    state->T[3][1] = mul(11, state->S[3][2]) ^ mul(13, state->S[3][3]) ^ mul(9, state->S[3][0]) ^ mul(14, state->S[3][1]);
    state->T[3][2] = mul(11, state->S[3][3]) ^ mul(13, state->S[3][0]) ^ mul(9, state->S[3][1]) ^ mul(14, state->S[3][2]);
    state->T[3][3] = mul(11, state->S[3][0]) ^ mul(13, state->S[3][1]) ^ mul(9, state->S[3][2]) ^ mul(14, state->S[3][3]);

    state->S[0][0] = state->T[0][0];
    state->S[0][1] = state->T[0][1];
    state->S[0][2] = state->T[0][2];
    state->S[0][3] = state->T[0][3];
    state->S[1][0] = state->T[1][0];
    state->S[1][1] = state->T[1][1];
    state->S[1][2] = state->T[1][2];
    state->S[1][3] = state->T[1][3];
    state->S[2][0] = state->T[2][0];
    state->S[2][1] = state->T[2][1];
    state->S[2][2] = state->T[2][2];
    state->S[2][3] = state->T[2][3];
    state->S[3][0] = state->T[3][0];
    state->S[3][1] = state->T[3][1];
    state->S[3][2] = state->T[3][2];
    state->S[3][3] = state->T[3][3];
}

void aes_add_round_key(struct aes_state *state, int r) {
    state->S[0][0] ^= state->K[r][0][0];
    state->S[0][1] ^= state->K[r][0][1];
    state->S[0][2] ^= state->K[r][0][2];
    state->S[0][3] ^= state->K[r][0][3];
    state->S[1][0] ^= state->K[r][1][0];
    state->S[1][1] ^= state->K[r][1][1];
    state->S[1][2] ^= state->K[r][1][2];
    state->S[1][3] ^= state->K[r][1][3];
    state->S[2][0] ^= state->K[r][2][0];
    state->S[2][1] ^= state->K[r][2][1];
    state->S[2][2] ^= state->K[r][2][2];
    state->S[2][3] ^= state->K[r][2][3];
    state->S[3][0] ^= state->K[r][3][0];
    state->S[3][1] ^= state->K[r][3][1];
    state->S[3][2] ^= state->K[r][3][2];
    state->S[3][3] ^= state->K[r][3][3];
}

void aes_ksa(struct aes_state *state, uint8_t *key) {
    state->rounds = 14;
    memset(state->K, 0, 14*4*4*(sizeof(uint8_t)));
    int i = 0;
    int Nk = 8;
    uint8_t W[60][4];
    while (i <= Nk - 1) {
        W[i][0] = key[(4 * i + 0)];
        W[i][1] = key[(4 * i + 1)];
        W[i][2] = key[(4 * i + 2)];
        W[i][3] = key[(4 * i + 3)];
        i += 1;
    }
    while (i <= (4 * state->rounds + 3)) {
        state->T[0][0] = W[i - 1][0];
        state->T[0][1] = W[i - 1][1];
        state->T[0][2] = W[i - 1][2];
        state->T[0][3] = W[i - 1][3];
        if ((i % Nk) == 0) {
            state->S[0][0] = state->T[0][0];
            state->S[0][1] = state->T[0][1];
            state->S[0][2] = state->T[0][2];
            state->S[0][3] = state->T[0][3];

            state->T[0][0] = state->S[0][1];
            state->T[0][1] = state->S[0][2];
            state->T[0][2] = state->S[0][3];
            state->T[0][3] = state->S[0][0];

            state->T[0][0] = aes_S0[state->T[0][0]];
            state->T[0][1] = aes_S0[state->T[0][1]];
            state->T[0][2] = aes_S0[state->T[0][2]];
            state->T[0][3] = aes_S0[state->T[0][3]];

            state->T[0][0] ^= aes_RC[i / Nk];
        }
        else if ((Nk > 6) && ((i % Nk) == 4)) {
            state->T[0][0] = aes_S0[state->T[0][0]];
            state->T[0][1] = aes_S0[state->T[0][1]];
            state->T[0][2] = aes_S0[state->T[0][2]];
            state->T[0][3] = aes_S0[state->T[0][3]];
        }
        W[i][0] = W[i - Nk][0] ^ state->T[0][0];
        W[i][1] = W[i - Nk][1] ^ state->T[0][1];
        W[i][2] = W[i - Nk][2] ^ state->T[0][2];
        W[i][3] = W[i - Nk][3] ^ state->T[0][3];
        i += 1;
    }
    state->K[0][0][0] = W[0][0];
    state->K[0][0][1] = W[0][1];
    state->K[0][0][2] = W[0][2];
    state->K[0][0][3] = W[0][3];
    state->K[0][1][0] = W[1][0];
    state->K[0][1][1] = W[1][1];
    state->K[0][1][2] = W[1][2];
    state->K[0][1][3] = W[1][3];
    state->K[0][2][0] = W[2][0];
    state->K[0][2][1] = W[2][1];
    state->K[0][2][2] = W[2][2];
    state->K[0][2][3] = W[2][3];
    state->K[0][3][0] = W[3][0];
    state->K[0][3][1] = W[3][1];
    state->K[0][3][2] = W[3][2];
    state->K[0][3][3] = W[3][3];
    state->K[14][0][0] = W[56][0];
    state->K[14][0][1] = W[56][1];
    state->K[14][0][2] = W[56][2];
    state->K[14][0][3] = W[56][3];
    state->K[14][1][0] = W[57][0];
    state->K[14][1][1] = W[57][1];
    state->K[14][1][2] = W[57][2];
    state->K[14][1][3] = W[57][3];
    state->K[14][2][0] = W[58][0];
    state->K[14][2][1] = W[58][1];
    state->K[14][2][2] = W[58][2];
    state->K[14][2][3] = W[58][3];
    state->K[14][3][0] = W[59][0];
    state->K[14][3][1] = W[59][1];
    state->K[14][3][2] = W[59][2];
    state->K[14][3][3] = W[59][3];
    int r = 1;
    int c = 0;
    for (int i = 4; i < (4 * (state->rounds)); i=i+4) {
        state->K[r][i & 0x03][0] = W[i][0];
        state->K[r][i & 0x03][1] = W[i][1];
        state->K[r][i & 0x03][2] = W[i][2];
        state->K[r][i & 0x03][3] = W[i][3];
        state->K[r][(i + 1) & 0x03][0] = W[i + 1][0];
        state->K[r][(i + 1) & 0x03][1] = W[i + 1][1];
        state->K[r][(i + 1) & 0x03][2] = W[i + 1][2];
        state->K[r][(i + 1) & 0x03][3] = W[i + 1][3];
        state->K[r][(i + 2) & 0x03][0] = W[i + 2][0];
        state->K[r][(i + 2) & 0x03][1] = W[i + 2][1];
        state->K[r][(i + 2) & 0x03][2] = W[i + 2][2];
        state->K[r][(i + 2) & 0x03][3] = W[i + 2][3];
        state->K[r][(i + 3) & 0x03][0] = W[i + 3][0];
        state->K[r][(i + 3) & 0x03][1] = W[i + 3][1];
        state->K[r][(i + 3) & 0x03][2] = W[i + 3][2];
        state->K[r][(i + 3) & 0x03][3] = W[i + 3][3];
        r += 1;
    }
}

void aes_encrypt_block(struct aes_state *state) {
    aes_add_round_key(state, 0);
    for (int r = 1; r < state->rounds; r++) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, r);
    }
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, 14);
}

void aes_decrypt_block(struct aes_state *state) {
    aes_add_round_key(state, 14);
    aes_shift_rows_inv(state);
    aes_sub_bytes_inv(state);
    for (int r = state->rounds - 1; r != 0; r--) {
        aes_add_round_key(state, r);
        aes_mix_columns_inv(state);
        aes_shift_rows_inv(state);
        aes_sub_bytes_inv(state);
    }
    aes_add_round_key(state, 0);
}

void aes_load_block(struct aes_state *state, uint8_t *block) {
    state->S[0][0] = block[0];
    state->S[0][1] = block[1];
    state->S[0][2] = block[2];
    state->S[0][3] = block[3];
    state->S[1][0] = block[4];
    state->S[1][1] = block[5];
    state->S[1][2] = block[6];
    state->S[1][3] = block[7];
    state->S[2][0] = block[8];
    state->S[2][1] = block[9];
    state->S[2][2] = block[10];
    state->S[2][3] = block[11];
    state->S[3][0] = block[12];
    state->S[3][1] = block[13];
    state->S[3][2] = block[14];
    state->S[3][3] = block[15];
}

void aes_unload_block(struct aes_state *state, uint8_t *block) {
    block[0] = state->S[0][0];
    block[1] = state->S[0][1];
    block[2] = state->S[0][2];
    block[3] = state->S[0][3];
    block[4] = state->S[1][0];
    block[5] = state->S[1][1];
    block[6] = state->S[1][2];
    block[7] = state->S[1][3];
    block[8] = state->S[2][0];
    block[9] = state->S[2][1];
    block[10] = state->S[2][2];
    block[11] = state->S[2][3];
    block[12] = state->S[3][0];
    block[13] = state->S[3][1];
    block[14] = state->S[3][2];
    block[15] = state->S[3][3];
}

void aes_load_iv(struct aes_state *state, uint8_t *iv) {
    state->last[0][0] = iv[0];
    state->last[0][1] = iv[1];
    state->last[0][2] = iv[2];
    state->last[0][3] = iv[3];
    state->last[1][0] = iv[4];
    state->last[1][1] = iv[5];
    state->last[1][2] = iv[6];
    state->last[1][3] = iv[7];
    state->last[2][0] = iv[8];
    state->last[2][1] = iv[9];
    state->last[2][2] = iv[10];
    state->last[2][3] = iv[11];
    state->last[3][0] = iv[12];
    state->last[3][1] = iv[13];
    state->last[3][2] = iv[14];
    state->last[3][3] = iv[15];
}

void aes_cbc_last(struct aes_state *state) {
    state->S[0][0] ^= state->last[0][0];
    state->S[0][1] ^= state->last[0][1];
    state->S[0][2] ^= state->last[0][2];
    state->S[0][3] ^= state->last[0][3];
    state->S[1][0] ^= state->last[1][0];
    state->S[1][1] ^= state->last[1][1];
    state->S[1][2] ^= state->last[1][2];
    state->S[1][3] ^= state->last[1][3];
    state->S[2][0] ^= state->last[2][0];
    state->S[2][1] ^= state->last[2][1];
    state->S[2][2] ^= state->last[2][2];
    state->S[2][3] ^= state->last[2][3];
    state->S[3][0] ^= state->last[3][0];
    state->S[3][1] ^= state->last[3][1];
    state->S[3][2] ^= state->last[3][2];
    state->S[3][3] ^= state->last[3][3];
}

void aes_cbc_next(struct aes_state *state) {
    state->last[0][0] = state->S[0][0];
    state->last[0][1] = state->S[0][1];
    state->last[0][2] = state->S[0][2];
    state->last[0][3] = state->S[0][3];
    state->last[1][0] = state->S[1][0];
    state->last[1][1] = state->S[1][1];
    state->last[1][2] = state->S[1][2];
    state->last[1][3] = state->S[1][3];
    state->last[2][0] = state->S[2][0];
    state->last[2][1] = state->S[2][1];
    state->last[2][2] = state->S[2][2];
    state->last[2][3] = state->S[2][3];
    state->last[3][0] = state->S[3][0];
    state->last[3][1] = state->S[3][1];
    state->last[3][2] = state->S[3][2];
    state->last[3][3] = state->S[3][3];
}

void aes_cbc_next_inv(struct aes_state *state) {
    state->next[0][0] = state->S[0][0];
    state->next[0][1] = state->S[0][1];
    state->next[0][2] = state->S[0][2];
    state->next[0][3] = state->S[0][3];
    state->next[1][0] = state->S[1][0];
    state->next[1][1] = state->S[1][1];
    state->next[1][2] = state->S[1][2];
    state->next[1][3] = state->S[1][3];
    state->next[2][0] = state->S[2][0];
    state->next[2][1] = state->S[2][1];
    state->next[2][2] = state->S[2][2];
    state->next[2][3] = state->S[2][3];
    state->next[3][0] = state->S[3][0];
    state->next[3][1] = state->S[3][1];
    state->next[3][2] = state->S[3][2];
    state->next[3][3] = state->S[3][3];
}

void aes_cbc_last_inv(struct aes_state *state) {
    state->last[0][0] = state->next[0][0];
    state->last[0][1] = state->next[0][1];
    state->last[0][2] = state->next[0][2];
    state->last[0][3] = state->next[0][3];
    state->last[1][0] = state->next[1][0];
    state->last[1][1] = state->next[1][1];
    state->last[1][2] = state->next[1][2];
    state->last[1][3] = state->next[1][3];
    state->last[2][0] = state->next[2][0];
    state->last[2][1] = state->next[2][1];
    state->last[2][2] = state->next[2][2];
    state->last[2][3] = state->next[2][3];
    state->last[3][0] = state->next[3][0];
    state->last[3][1] = state->next[3][1];
    state->last[3][2] = state->next[3][2];
    state->last[3][3] = state->next[3][3];
}

void aes_cbc_encrypt(char *inputfile, char *outputfile, char *pkfile) {
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

    struct aes_state state;
    aes_ksa(&state, key);
    int blocklen = 16;
    int bufsize = 16;
    uint8_t iv[blocklen];
    urandom(iv, blocklen);
    aes_load_iv(&state, iv);
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
        aes_load_block(&state, block);
        aes_cbc_last(&state);
        aes_encrypt_block(&state);
        aes_cbc_next(&state);
        aes_unload_block(&state, block);
        fwrite(block, 1, blocklen, outfile);
    }
    fclose(infile);
    fclose(outfile);
    uint8_t kdf_key[32];
    qx_kdf(key, 32, kdf_key, 10000);
    qx_hmac_file_write(outputfile, kdf_key);
}

void aes_cbc_decrypt(char *inputfile, char *outputfile, char *skfile) {
    struct ecc_elgamal_ctx ctx;
    load_skfile(skfile, &ctx);
    uint8_t key[32];

    struct aes_state state;
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
    aes_load_iv(&state, iv);
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
    aes_ksa(&state, key);

    for (uint32_t b = 0; b < blocks; b++) {
        uint8_t block[16];
        fread(block, 1, blocklen, infile);
        aes_load_block(&state, block);
        aes_cbc_next_inv(&state);
        aes_decrypt_block(&state);
        aes_cbc_last(&state);
        aes_cbc_last_inv(&state);
        aes_unload_block(&state, block);
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
