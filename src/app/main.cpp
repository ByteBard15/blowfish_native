#include <cstring>
#include <iostream>
#include <string>
#include <bits/ostream.tcc>

#include "bcrypt.h"

int main() {
    const char* input_text = "Hello!";
    u_int16_t input_len = static_cast<u_int16_t>(std::strlen(input_text));

    // 2. Calculate required buffer size
    // Formula: (n * 4 / 3) + padding + null terminator
    // For "Hello!" (6 bytes), it should be exactly 8 chars + 1
    u_int8_t output_buffer[64];

    // 3. Call your function
    // We cast the char* to u_int8_t* to match your signature
    encode_base64_v2(output_buffer, (u_int8_t*)input_text, input_len);

    // 4. Output the results
    std::cout << "Input String:  " << input_text << std::endl;
    std::cout << "Input Bytes:   ";
    for(int i = 0; i < input_len; i++) printf("%02x ", (u_int8_t)input_text[i]);

    std::cout << "\nBcrypt Base64: " << output_buffer << std::endl;

    return 0;
}