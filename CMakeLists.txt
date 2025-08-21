cmake_minimum_required(VERSION 3.10)

project(rijndael VERSION 0.1.0 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

file(TO_CMAKE_PATH $ENV{MOON_BIN} MOON_BIN)
include_directories(${MOON_BIN}/../include)

add_library(rijndael STATIC
    src/native/rijndael-alg-fst.c
    src/native/stub.c
)