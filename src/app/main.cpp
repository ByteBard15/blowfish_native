#include <cstring>
#include <iostream>
#include <string>
#include <bits/ostream.tcc>

#include "bcrypt.h"
#include "blowfish.h"

int main() {
    const char *seed = "Hello World!";
    const auto len = std::strlen(seed);
    char salt[(len * 4 / 3) + 7];

    bcrypt_gen_salt('a', 10, reinterpret_cast<u_int8_t *>(const_cast<char*>(seed)), salt);
    std::cout << "Generated Salt: " << salt << std::endl;

    std::string password = "Hello world!";
    std::string salt_str = std::string(salt);
    std::string hash = bcrypt_hash(password, salt_str);
    std::cout << "Hashed: " << hash << std::endl;

    return 0;
}
