#include "bcrypt.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>

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

void encode_base64_v2(u_int8_t *buf, const u_int8_t *data, const u_int16_t len) {
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

void encode_salt(char *salt, u_int8_t *c_salt, char minor, u_int16_t c_len, u_int8_t log_r) {
    salt[0] = '$';
    salt[1] = BCRYPT_VERSION;
    salt[2] = minor;
    salt[3] = '$';

    encode_base64(reinterpret_cast<u_int8_t *>(salt + 7), c_salt, c_len);
}

void bcrypt_gen_salt(char minor, u_int8_t log_rounds, u_int8_t *seed, char *g_salt) {
    log_rounds = log_rounds < 4 ? 4 : (log_rounds > 31 ? 31 : log_rounds);

    encode_salt(g_salt, seed, minor, BCRYPT_MAX_SALT, log_rounds);
}

u_int32_t bcrypt_get_rounds(const char * hash) {
    if (!hash || *(hash++) != '$') return 0;

    if (0 == (*hash++)) return 0;
    if (*hash && *hash != '$') return 0;
    if (*hash++ != '$') return 0;

    return atoi(hash);
}

void bcrypt_hash(std::string& key, std::string& salt_str) {
    blowfish_context ctx;
    u_int8_t salt_bytes[BCRYPT_MAX_SALT];
    u_int32_t c_data[BCRYPT_BLOCKS];

    u_int8_t cipher_text[24] = {'O','r','p','h','e','a','n','B','e','h','o','l','d','e','r','S','c','r','y','D','o','u','b','t'};

    // --- 1. PARSE VERSION ---
    // Standard format: $2[a,b,y]$
    if (salt_str.length() < 4 || salt_str[0] != '$' || salt_str[1] != '2') {
        throw std::runtime_error("Invalid bcrypt prefix: missing '$2'");
    }

    char minor = 0;
    size_t pos = 2;

    if (salt_str[pos] != '$') {
        minor = salt_str[pos]; // a, b or y
        pos++;
    }

    if (salt_str[pos] != '$') {
        throw std::runtime_error("Invalid bcrypt format: expected '$' after version");
    }
    pos++;

    // --- 2. PARSE COST (ROUNDS) ---
    if (pos + 2 >= salt_str.length() || salt_str[pos+2] != '$') {
        throw std::runtime_error("Invalid bcrypt format: cost factor improperly formatted");
    }

    int cost_val = std::stoi(salt_str.substr(pos, 2));
    if (cost_val < 4 || cost_val > 31) {
        throw std::runtime_error("Cost factor out of range (4-31)");
    }

    u_int32_t total_rounds = (1U << cost_val);
    pos += 3; // Move past "12$"

    // ---- 3. DECODE SALT -------
    std::string encoded_salt = salt_str.substr(pos);
    if (encoded_salt.length() < 22) {
        throw std::runtime_error("Salt string is too short, expected 22 base64 characters");
    }

    decode_base64(salt_bytes, BCRYPT_MAX_SALT, reinterpret_cast<u_int8_t *>(const_cast<char *>(encoded_salt.c_str())));

    // --- 4. KEY LENGTH HANDLING ---
    size_t effective_key_len = key.length();
    if (minor >= 'a') {
        if (effective_key_len > 71) effective_key_len = 72;
        effective_key_len++;
    }

    auto c_key = reinterpret_cast<u_int8_t*>(const_cast<char *>(key.c_str()));
    blf_init_state(&ctx);
    blf_expand_state(&ctx, salt_bytes, BCRYPT_MAX_SALT, c_key, effective_key_len);

    // --- 5. EKSBLOWFISH (Expensive Key Setup) ---
    // The core loop: repeatedly re-scramble S-boxes using Key then Salt
    for (u_int32_t i = 0; i < total_rounds; i++) {
        blf_expand_0_state(&ctx, c_key, effective_key_len);
        blf_expand_0_state(&ctx, salt_bytes, BCRYPT_MAX_SALT);
    }

    // --- 6. DATA ENCRYPTION ---
    // Convert the magic string into 32-bit word
    u_int16_t stream_idx = 0;
    for (int i = 0; i < BCRYPT_BLOCKS; ++i) {
        c_data[i] = blf_stream_to_word(cipher_text, 24, &stream_idx);
    }

    for (int i = 0; i < 64; ++i) {
        blf_enc(&ctx, c_data, BCRYPT_BLOCKS / 2);
    }

    for (int i = 0; i < BCRYPT_BLOCKS; ++i) {
        cipher_text[4 * i + 3] = c_data[i] & 0xff;
        c_data[i] = c_data[i] >> 8;
        cipher_text[4 * i + 2] = c_data[i] & 0xff;
        c_data[i] = c_data[i] >> 8;
        cipher_text[4 * i + 1] = c_data[i] & 0xff;
        c_data[i] = c_data[i] >> 8;
        cipher_text[4 * i] = c_data[i] & 0xff;
    }

    // --- 7. FORMAT OUTPUT ---
    // Reassemble the binary 'c_data' into the final hash string
    return format_bcrypt_output(minor, cost_val, salt_bytes, c_data);
}

std::string format_bcrypt_output(char minor, int cost, u_int8_t* salt, u_int32_t *c_data) {
    char result[61];
    int pos = 0;

    result[pos++] = '$';
    result[pos++] = '2';
    if (minor) result[pos++] = minor;
    result[pos++] = '$';

    snprintf(result + pos, 4, "%02u$", cost & 0x1F);
    pos += 3;

    encode_base64()
}
