#include "bcrypt.h"

void blf_encipher(blowfish_context *ctx, u_int32_t *xl, u_int32_t *xr) {
    u_int32_t l, r;
    u_int32_t *s_box = ctx->S[0];
    u_int32_t *p_box = ctx->P;

    l = *xl;
    r = *xr;

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

}