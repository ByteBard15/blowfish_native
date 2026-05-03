#include "bcrypt.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <format>
#include <stdexcept>
#include <string>

#include "blowfish.h"

void encode_salt(char *salt, u_int8_t *c_salt, char minor, u_int16_t c_len, u_int8_t log_r) {
    salt[0] = '$';
    salt[1] = BCRYPT_VERSION;
    salt[2] = minor;
    salt[3] = '$';

    u_int8_t masked_logr = 0x1F & log_r;
    std::string cost_str = std::format("{:02}$", masked_logr);
    memcpy(salt + 4, cost_str.c_str(), 3);
    encode_base64(reinterpret_cast<u_int8_t *>(salt + 7), c_salt, c_len);
}

void bcrypt_gen_salt(char minor, u_int8_t log_rounds, u_int8_t *seed, char *output) {
    log_rounds = log_rounds < 4 ? 4 : (log_rounds > 31 ? 31 : log_rounds);

    encode_salt(output, seed, minor, BCRYPT_MAX_SALT, log_rounds);
}

u_int32_t bcrypt_get_rounds(const char * hash) {
    if (!hash || *(hash++) != '$') return 0;

    if (0 == (*hash++)) return 0;
    if (*hash && *hash != '$') return 0;
    if (*hash++ != '$') return 0;

    return atoi(hash);
}

std::string format_bcrypt_output(char minor, int cost, u_int8_t* salt, u_int8_t *cipher_text) {
    char result[61];
    int pos = 0;

    result[pos++] = '$';
    result[pos++] = '2';
    if (minor) result[pos++] = minor;
    result[pos++] = '$';

    snprintf(result + pos, 4, "%02u$", cost & 0x1F);
    pos += 3;

    encode_base64(reinterpret_cast<u_int8_t *>(result + pos), salt, BCRYPT_MAX_SALT);
    pos += 22;
    encode_base64(reinterpret_cast<u_int8_t *>(result + pos), cipher_text, 24);

    return std::string(result);
}

std::string bcrypt_hash(std::string& key, std::string& salt_str) {
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
    return format_bcrypt_output(minor, cost_val, salt_bytes, cipher_text);
}
