#!/bin/bash

export CC="$SLEUTH_PATH/Sleuth/afl-clang-fast"
export CXX="$SLEUTH_PATH/Sleuth/afl-clang-fast++"
export LD="$SLEUTH_PATH/Sleuth/afl-clang-fast"
export CFLAGS="-g -O0"
export CXXFLAGS="-g -O0"
export AFL_USE_ASAN=1
export FUZZALLOC_INST="tracer"
export FUZZALLOC_USE_SENSITIVITY="read:write"
export FUZZALLOC_DEF_SENSITIVITY="array:struct:pointer"

