## Setup your environment 

If not using docker, please follow these steps to set up your environment (assumes a modern Ubuntu OS, `>= 18.04 && <= 20.04` with `LLVM v12` and `Python 3.8`):

```bash
sudo apt-get update
sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev screen
sudo apt-get install -y lld-12 llvm-12 llvm-12-dev clang-12 || sudo apt-get install -y lld llvm llvm-dev clang
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
pip install contourpy==1.1.0 cycler==0.11.0 fonttools==4.40.0 importlib-resources==5.12.0 kiwisolver==1.4.4 matplotlib==3.7.1 numpy==1.24.3 packaging==23.1 pandas==2.0.3 Pillow==9.5.0 pip==20.0.2 Pygments==2.3.1 pyparsing==3.1.0 python-dateutil==2.8.2 pytz==2024.1 PyYAML==5.3.1 scipy==1.10.1 setuptools==45.2.0 six==1.16.0 tzdata==2024.1 wheel==0.34.2 wllvm==1.3.1 xlwt==1.3.0 zipp==3.15.0
```

`ddgAnalysis` is our static analyzer for generating memory relevant graph. It depends on the support of `SVF` and `z3`. To build:

1. Build z3

   ```bash
   export SLEUTH_PATH=/path/to/Sleuth_code     # replace to your path
   cd $SLEUTH_PATH/ddgAnalysis
   git clone https://github.com/z3prover/z3
   git -C z3 checkout z3-4.8.8
   mkdir -p z3/build
   cd z3/build
   cmake .. \
       -DCMAKE_INSTALL_PREFIX=$(realpath ../install) -DZ3_BUILD_LIBZ3_SHARED=False
   make -j
   make install
   ```

   Don't forget set the `SLEUTH_PATH`, which stores the source code.

2. Build ddgAnalysis

   ```bash
   cd $SLEUTH_PATH/ddgAnalysis
   mkdir build
   cd build
   cmake .. \
       -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
       -DLLVM_DIR=$(llvm-config --cmakedir) \
       -DZ3_DIR=/path/to/z3/install
   make -j
   ```

`Sleuth` is our primary tool for exploring bug impacts, based on AFLplusplus. To build:

```bash
cd $SLEUTH_PATH/Sleuth
make source-only NO_SPLICING=1      # Don't forget NO_SPLICING=1
```

