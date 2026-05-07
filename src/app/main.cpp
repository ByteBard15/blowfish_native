#include <array>
#include <cstring>
#include <iostream>
#include <random>
#include <string>
#include <bits/ostream.tcc>

#include "bcrypt.h"
#include "blowfish.h"

template <std::size_t N>
std::array<unsigned char, N> random_bytes() {
    std::array<unsigned char, N> bytes{};
    std::random_device rd;

    for (auto &b : bytes) {
        b = static_cast<unsigned char>(rd());
    }

    return bytes;
}

int main() {
    auto bytes = random_bytes<16>();
    auto seed = bytes.data();
    const auto len = bytes.size();
    constexpr size_t kBcryptSaltChars = 29; // "$2b$12$" + 22-char bcrypt base64 salt
    std::string salt(kBcryptSaltChars, '\0');

    bcrypt_gen_salt('a', 10, reinterpret_cast<u_int8_t *>(reinterpret_cast<char*>(seed)), salt.data());

    std::string password = "Hello world!";
    std::string salt_str = std::string(salt);
    std::string hash = bcrypt_hash(password, salt_str);

    return 0;
}
