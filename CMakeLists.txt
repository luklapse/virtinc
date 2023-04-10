#cmake 版本
cmake_minimum_required(VERSION 3.8)
project(demo CXX)
set(CMAKE_C_FLAGS -std=c++17 -O2 -Wall -g )
include_directories(./src)
add_executable(demo main.cpp)
target_link_libraries(demo pthread pcap)