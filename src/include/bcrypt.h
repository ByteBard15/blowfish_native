#ifndef _BCRYPT_H_
#define _BCRYPT_H_

#include <sys/types.h>

#ifdef __sun
#define u_int8_t uint8_t
#define u_int16_t uint16_t
#define u_int32_t uint32_t
#define u_int64_t uint64_t
#endif

#ifdef _WIN32
#define u_int8_t unsigned __int8
#define u_int16_t unsigned __int16
#define u_int32_t unsigned __int32
#define u_int64_t unsigned __int64
#endif

#if defined(_WIN32) || defined(_WIN64)
#if defined(_WIN64)
typedef __int64 LONG_PTR;
#else
typedef long LONG_PTR;
#endif
typedef LONG_PTR SSIZE_T;
typedef SSIZE_T ssize_t;
#endif

#ifdef __MVS__
typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
typedef unsigned long long u_int64_t;
#endif

#define BCRYPT_VERSION '2'
#define BCRYPT_MAX_SALT 16
#define BCRYPT_BLOCKS 6
#define BCRYPT_MIN_ROUNDS 16

#define BLF_N 16
#define BLF_MAX_KEY_LEN ((BLF_N - 2) * 4)
#define BLF_MAX_UTILIZED ((BLF_N + 2) * 4)

#define _MAX_PASSWORD_LENGTH 128
#define _MAX_SALT_LENGTH 32

struct blowfish_context {
    u_int32_t S[4][256];
    u_int32_t P[BLF_N + 2];
};

constexpr u_int32_t f_networks(u_int32_t* s_box, u_int32_t x) {
    auto f_byte = s_box[(x >> 24) & 0xff];
    auto s_byte = s_box[0x100 + ((x >> 16) & 0xff)];
    auto t_byte = s_box[0x200 + ((x >> 8) & 0xff)];
    auto f_t_byte = s_box[0x300 + (x & 0xff)];

    return f_byte + s_byte ^ t_byte + f_t_byte;
}

constexpr u_int32_t blf_rn(u_int32_t *s_box, u_int32_t *p_box, u_int32_t xl, u_int32_t xr, u_int32_t n) {
    xl ^= f_networks(s_box, xr);
    return xl ^ p_box[n];
}

void blf_encipher(blowfish_context *, u_int32_t *, u_int32_t *);
void blf_decipher(blowfish_context *, u_int32_t *, u_int32_t *);
void blf_init_state(blowfish_context *);
void blf_expand_0_state(blowfish_context *, const u_int8_t *, u_int16_t);
void blf_expand_state(blowfish_context *, const u_int8_t *, u_int16_t, const u_int8_t *, u_int16_t);

void blf_key(blowfish_context *, const u_int8_t *, u_int16_t);
void blf_enc(blowfish_context *, u_int32_t *, u_int16_t);
void blf_dec(blowfish_context *, u_int32_t *, u_int16_t);

void blf_ecb_encrypt(blowfish_context *, u_int8_t *, u_int32_t);
void blf_ecb_decrypt(blowfish_context *, u_int8_t *, u_int32_t);

void blf_cbc_encrypt(blowfish_context *, u_int8_t *, u_int8_t *, u_int32_t);
void blf_cbc_decrypt(blowfish_context *, u_int8_t *, u_int8_t *, u_int32_t);

u_int32_t blf_stream_to_word(const u_int8_t *, u_int16_t, u_int16_t *);

void bcrypt_gen_salt(char, u_int8_t, u_int8_t *, char *);
void bcrypt(const char *, size_t key_len, const char *, char *);
void encode_salt(char *, u_int8_t *, char, u_int16_t, u_int8_t);
u_int32_t bcrypt_get_rounds(const char *);

#endif
