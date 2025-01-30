cmake_minimum_required(VERSION 3.30)
project(c_proj C)

set(CMAKE_C_STANDARD 11)

link_directories(/usr/local/opt/openssl/lib)
include_directories(/usr/local/opt/openssl/include)
add_executable(c_proj keygen.c)
target_link_libraries(c_proj crypto)
