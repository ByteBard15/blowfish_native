cmake_minimum_required(VERSION 3.31)
project(bcrypt_js)

set(CMAKE_CXX_STANDARD 20)

file (GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/*.cpp")

add_executable(bcrypt_js main.cpp)

target_include_directories(
        ${PROJECT_NAME}
        PRIVATE
        ${CMAKE_SOURCE_DIR}/src/include
)