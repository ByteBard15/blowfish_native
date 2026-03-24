#include "blowfish.h"

/**
 * This function performs the actual scrambling of data. Blowfish is a Feistal network, meaning
 * it splits 64-bit block into two 32-bit halves (L and D).
 * Initial XOR (xl ^ p_box[0]): It xor's the left half(xl) with the first entry in the P-box array
 * The Rounds: It runs a loop for 16 rounds. In each round, it calls blf_rn (the round function).
 *  This blf_n function
 */
void blf_encipher(blowfish_context *ctx, u_int32_t *xl, u_int32_t *xr) {
    u_int32_t *s_box = ctx->S[0];
    u_int32_t *p_box = ctx->P;

    u_int32_t l = *xl;
    const u_int32_t r = *xr;

    l ^= p_box[0];

    for (int i = 1; i <= 16; ++i) {
        blf_rn(s_box, p_box, l, r, i);
    }

    *xl = r ^ p_box[17];
    *xr = l;
}

void blf_decipher(blowfish_context *ctx, u_int32_t *xl, u_int32_t *xr) {
    u_int32_t l, r;
    u_int32_t *s_box = ctx->S[0];
    u_int32_t *p_box = ctx->P;

    l = *xl;
    r = *xr;

    l ^= p_box[17];
    for (int i = 16; i >= 0; i--) {
        blf_rn(s_box, p_box, l, r, i);
    }
    *xl = r ^ p_box[0];
    *xr = l;
}

u_int32_t blf_stream_to_word(const u_int8_t *data, u_int16_t data_bytes, u_int16_t *current) {
    u_int32_t temp = 0x000000;
    u_int16_t j = *current;

    for (u_int8_t start = 0; start < 4; start++, j++) {
        if (j >= data_bytes) {
            j = 0;
        }
        temp = (temp << 8) | data[j];
    }

    *current = j;
    return temp;
}

void blf_expand_0_state(blowfish_context *ctx, const u_int8_t *key, u_int16_t k_bytes) {
    u_int16_t i, j;
    u_int32_t data_l, data_r;

    j = 0;

    for (i = 0; i < BLF_N + 2; i++) {
        const u_int32_t temp = blf_stream_to_word(key, k_bytes, &j);
        ctx->P[i] = ctx->P[i] ^ temp;
    }

    j = 0;
    data_l = 0x00000000;
    data_r = 0x00000000;

    for (i = 0; i < BLF_N + 2; i += 2) {
        blf_encipher(ctx, &data_l, &data_r);
        ctx->P[i] = data_l;
        ctx->P[i + 1] = data_r;
    }

    for (i = 0; i < 4; ++i) {
        for (u_int16_t k = 0; k < 256; k += 2) {
            blf_encipher(ctx, &data_l, &data_r);

            ctx->S[i][k] = data_l;
            ctx->S[i][k + 1] = data_r;
        }
    }
}

void blf_expand_state(blowfish_context *ctx, const u_int8_t *data, u_int16_t d_bytes, const u_int8_t *key, u_int16_t k_bytes) {
    u_int16_t i, j = 0;

    for (i = 0; i < BLF_N + 2; i += 2) {
        u_int32_t temp = blf_stream_to_word(key, k_bytes, &j);
        ctx->P[i] = ctx->P[i] ^ temp;
    }

    j = 0;
    u_int32_t data_l = 0x00000000;
    u_int32_t data_r = 0x00000000;

    for (i = 0; i < BLF_N + 2; i += 2) {
        data_l ^= blf_stream_to_word(data, d_bytes, &j);
        data_r ^= blf_stream_to_word(data, d_bytes, &j);
        blf_encipher(ctx, &data_l, &data_r);

        ctx->P[i] = data_l;
        ctx->P[i + 1] = data_r;
    }

    for (i = 0; i < 4; ++i) {
        for (int k = 0; k < 256; k += 2) {
            data_l ^= blf_stream_to_word(data, d_bytes, &j);
            data_r ^= blf_stream_to_word(data, d_bytes, &j);

            ctx->S[i][k] = data_l;
            ctx->S[i][k + 1] = data_r;
        }
    }
}

void blf_key(blowfish_context *ctx, const u_int8_t *key, u_int16_t len) {
    blf_init_state(ctx);
    blf_expand_0_state(ctx, key, len);
}

void blf_enc(blowfish_context *ctx, u_int32_t *data, u_int16_t blocks) {
    u_int32_t *d = data;
    u_int16_t i;

    for (i = 0; i < blocks; ++i) {
        blf_encipher(ctx, d, d + 1);
        d += 2;
    }
}

void blf_dec(blowfish_context *ctx, u_int32_t *data, u_int16_t blocks) {
    u_int32_t *d = data;

    for (u_int16_t i = 0; i < blocks; ++i) {
        blf_decipher(ctx, d, d + 1);
        d += 2;
    }
}

void fill_in_bytes(u_int8_t *data, u_int32_t l, u_int32_t r) {
    data[0] = l >> 24 & 0xff;
    data[1] = (l >> 16) & 0xff;
    data[2] = (l >> 8) & 0xff;
    data[3] = l & 0xff;

    data[4] = r >> 24 & 0xff;
    data[5] = (r >> 16) & 0xff;
    data[6] = (r >> 8) & 0xff;
    data[7] = r & 0xff;
}

void blf_ecb_encrypt(blowfish_context *ctx, u_int8_t *data, const u_int32_t len) {
    for (u_int16_t i = 0; i < len; i += 8) {
        u_int32_t l = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
        u_int32_t r = data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7];

        blf_encipher(ctx, &l, &r);
        fill_in_bytes(data, l, r);
        data += 8;
    }
}

void blf_ecb_decrypt(blowfish_context *ctx, u_int8_t *data, u_int32_t len) {
    for (u_int16_t i = 0; i < len; i += 8) {
        u_int32_t l = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
        u_int32_t r = data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7];

        blf_decipher(ctx, &l, &r);
        fill_in_bytes(data, l, r);
        data += 8;
    }
}

void blf_cbc_encrypt(blowfish_context *ctx, u_int8_t *iv, u_int8_t *data, u_int32_t len) {
    for (u_int16_t i = 0; i < len; i += 8) {
        for (u_int16_t j = 0; j < 8; ++j) {
            data[j] ^= iv[j];
        }

        u_int32_t l = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
        u_int32_t r = data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7];

        blf_encipher(ctx, &l, &r);
        fill_in_bytes(data, l, r);
        data += 8;
    }
}

void blf_cbc_decrypt(blowfish_context *ctx, u_int8_t *iva, u_int8_t *data, u_int32_t len) {
    const u_int8_t *iv = data + len - 16;
    data = data + len - 8;

    for (u_int16_t i = len - 8; i >= 8; i -= 8) {
        u_int32_t l = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
        u_int32_t r = data[3] << 24 | data[4] << 16 | data[5] << 8 | data[6];

        blf_decipher(ctx, &l, &r);
        fill_in_bytes(data, l, r);

        for (u_int16_t j = 0; j < 8; ++j) {
            data[j] ^= iv[j];
        }
        iv -= 8;
        data -= 8;
    }

    u_int32_t l = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
    u_int32_t r = data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7];

    blf_decipher(ctx, &l, &r);
    fill_in_bytes(data, l, r);

    for (u_int16_t j = 0; j < 8; ++j) {
        data[j] ^= iva[j];
    }
}

void blf_init_state(blowfish_context *c) {

}



