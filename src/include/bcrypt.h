#ifndef _BCRYPT_H_
#define _BCRYPT_H_

#include <sys/types.h>

#include "blowfish.h"

void encode_base64(u_int8_t *, u_int8_t *, u_int16_t);
void decode_base64(u_int8_t *buf, u_int16_t len, u_int8_t *data);

static auto error = ":";

static constexpr u_int8_t base_64_code[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static u_int8_t index_64[128] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 0, 1, 54, 55,
    56, 57, 58, 59, 60, 61, 62, 63, 255, 255,
    255, 255, 255, 255, 255, 2, 3, 4, 5, 6,
    7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    255, 255, 255, 255, 255, 255, 28, 29, 30,
    31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 255, 255, 255, 255, 255
};

constexpr u_int8_t to_base_64(u_int8_t ch) {
    return ch > 127 ? 255 : index_64[ch];
}

#endif
