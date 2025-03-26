

cmake_minimum_required(VERSION 3.29)
project(Openssl_App_Provider C)

set(CMAKE_C_STANDARD 11)

#Change with the correct path
set(OPENSSL_ROOT_DIR "C:\\...\\bin")
set(OPENSSL_INCLUDE_DIR "C:\\...\\include")
set(OPENSSL_LIB_DIR "C:\\...\\MD")

s
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(Openssl_App_Provider main.c
)

target_link_libraries(Openssl_App_Provider "C:\\...OpenSSL-Win64\\lib\\VC\\x64\\MD\\libcrypto.lib")


