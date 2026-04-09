#include "bcrypt.h"

void decode_base64(u_int8_t *buf, u_int16_t len, u_int8_t *data) {
    u_int8_t *bp = buf;
    u_int8_t *p = data;

    while (bp < buf + len) {
        u_int8_t d_c1 = to_base_64(*p);
        u_int8_t d_c2 = to_base_64(*(p + 1));

        if (is_invalid_base64_char(d_c1) || is_invalid_base64_char(d_c2)) {
            break;
        }

        u_int8_t b_c1 = (d_c1 << 2) | ((d_c2 & 0x30) >> 4);
        *bp++ = b_c1;

        if (bp >= buf + len) {
            break;
        }

        u_int8_t d_c3 = to_base_64(*(p + 2));
        if (is_invalid_base64_char(d_c3)) {
            break;
        }
        u_int8_t b_c2 = ((d_c2 & 0x0f) << 4) | ((d_c3 >> 2) & 0x0f);
        *bp++ = b_c2;
        if (bp >= buf + len) {
            break;
        }
        u_int8_t d_c4 = to_base_64(*(p + 3));
        if (is_invalid_base64_char(d_c4)) {
            break;
        }
        u_int8_t b_c3 = ((d_c3 & 0x03) << 6) | (d_c4 & 0x3f);
        *bp++ = b_c3;

        p += 4;
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
        u_int8_t r_c1 = (d_c1 & 0x03) << 4;

        if (p >= data + len) {
            *bp++ = to_base_64(r_c1 & 0x3f);
            break;
        }
        u_int8_t d_c2 = *p++;
        u_int8_t b_c2 = to_base_64(r_c1 | (d_c2 >> 4));
        *bp++ = b_c2;

        // remaining c2
        u_int8_t r_c2 = (d_c2 & 0x0f) << 2;
        if (p >= data + len) {
            *bp++ = to_base_64(r_c2);
            break;
        }

        u_int8_t d_c3 = *p++;
        u_int8_t b_c3 = to_base_64(r_c2 | ((d_c3 >> 6) & 0x03));
        *bp++ = b_c3;

        u_int8_t b_c4 = to_base_64(d_c3 & 0x3f);
        *bp++ = b_c4;
    }
    *bp = '\0';
}

void encode_base64_v2(u_int8_t *buf, u_int8_t *data, u_int16_t len) {
    const u_int8_t *p = buf;
    u_int8_t *bp = buf;

    while (p < data + len) {
        u_int32_t v = *p++ << 16;
        if (p < data + len) v |= *p++ << 8;
        if (p < data + len) v |= *p++;

        *bp++ = to_base_64((v >> 18) & 0x3f);
        *bp++ = to_base_64((v >> 12) & 0x3f);

        if (bp - buf >= (len * 4 / 3)) break;

        *bp++ = to_base_64((v >> 6) & 0x3f);
        *bp++ = to_base_64(v & 0x3f);
    }
    *bp = '\0';
}