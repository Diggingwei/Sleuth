#!/bin/bash

export CC="$SLEUTH_PATH/AFLplusplus/afl-clang-fast"
export CXX="$SLEUTH_PATH/AFLplusplus/afl-clang-fast++"
export LD="$SLEUTH_PATH/AFLplusplus/afl-clang-fast"
export CFLAGS="-g -O0"
export CXXFLAGS="-g -O0"
export AFL_USE_ASAN=1
