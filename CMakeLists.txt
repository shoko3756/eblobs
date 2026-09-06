cmake_minimum_required(VERSION 3.16)
project(emailblob VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(emailblob
  src/main.cpp
  src/imap.cpp
  src/mime.cpp
)

target_link_libraries(emailblob PRIVATE OpenSSL::SSL OpenSSL::Crypto)