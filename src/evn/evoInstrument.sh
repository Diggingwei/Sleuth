#!/bin/bash

export CC="$SLEUTH_PATH/Evocatio/bug-severity-AFLplusplus/afl-cc"
export CXX="$SLEUTH_PATH/Evocatio/bug-severity-AFLplusplus/afl-c++"
export LD="$SLEUTH_PATH/Evocatio/bug-severity-AFLplusplus/afl-cc"
export CFLAGS="-g -O0"
export CXXFLAGS="-g -O0"
export AFL_USE_ASAN=1
