#include "bcrypt.h"

void decode_base64(u_int8_t *buf, u_int16_t len, u_int8_t *data) {
    u_int8_t *bp = buf;
    u_int8_t *p = data;

    while (bp < buf + len) {
        u_int8_t c1 = to_base_64(*p);
        u_int8_t c2 = to_base_64(*(p + 1));
    }
}

void encode_base64(u_int8_t *buf, u_int8_t *data, u_int16_t len) {
    u_int8_t *bp = buf;
    u_int8_t *p = data;

    while (p < data + len) {
        u_int8_t d_c1 = *p++;
        u_int8_t b_c1 = to_base_64(d_c1 >> 2);
        *bp++ = b_c1;

        // remaining c1
        u_int8_t r_c1 = d_c1 & 0x03;

        if (p >= data + len) {
            *bp++ = to_base_64((r_c1 << 4));
            break;
        }
        u_int8_t d_c2 = *p++;
        u_int8_t b_c2 = to_base_64((r_c1 << 4) | (d_c2 >> 4));
        *bp++ = b_c2;

        // remaining c2
        u_int8_t r_c2 = d_c2 & 0x0f;
        if (p >= data + len) {
            *bp++ = to_base_64((r_c2 << 2));
            break;
        }

        u_int8_t d_c3 = *p++;
        u_int8_t b_c3 = to_base_64((r_c2 << 4) | (d_c3 >> 6));
        *bp++ = b_c3;

        u_int8_t b_c4 = to_base_64(d_c3 & 0x3f);
        *bp++ = b_c4;
    }
    *bp = '\0';
}

