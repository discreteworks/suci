cmake_minimum_required (VERSION 2.8.11)
project (suci)

find_package(PkgConfig REQUIRED)
pkg_check_modules(wolfssl REQUIRED IMPORTED_TARGET wolfssl)

add_executable (${PROJECT_NAME} src/main.c src/suci.c)

target_link_libraries ( suci wolfssl )



