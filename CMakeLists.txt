cmake_minimum_required(VERSION 3.31)
project(bcrypt_js)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(
        bcrypt_core STATIC
        src/bcrypt/base64.cpp
        src/bcrypt/bcrypt.cpp
        src/bcrypt/blowfish.cpp
)
target_include_directories(bcrypt_core PUBLIC src/bcrypt/include)

add_executable(bcrypt_cli src/app/main.cpp)
target_link_libraries(bcrypt_cli PRIVATE bcrypt_core)
target_compile_options(bcrypt_cli PRIVATE -Wall -Wextra -pedantic)
