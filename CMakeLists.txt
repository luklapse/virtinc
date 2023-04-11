#cmake 版本
cmake_minimum_required(VERSION 3.8)
project(demo CXX)
add_compile_options(-Wall -g -O2)
include_directories(./src)
add_executable(demo main.cpp)
target_link_libraries(demo pthread pcap)