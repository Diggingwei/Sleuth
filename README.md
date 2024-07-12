# Sleuth: A Switchable Dual-Mode Fuzzer to Investigate Bug Impacts Following a Single PoC

### Overview

Sleuth is an open-source fuzzer for automatically discovering bug impacts following a single PoC. It is based on [LLVM](https://github.com/llvm/llvm-project.git) and the fuzzing tool [AFL++](https://github.com/AFLplusplus/AFLplusplus.git). It employs [SVF](https://github.com/SVF-tools/SVF.git) to construct the memory-relevant graph, and utilizes this graph to guide Fuzzer to efficiently discover new bug impacts. 

The current version still has some cumbersome user interactions. We will optimize this part in the future and release a more stable version.

### Requirements

##### Docker Container

We recommend using docker to quickly set up Sleuth's usage environment. We provide a docker container which can be downloaded from [Docker Hub]([The World’s Largest Container Registry | Docker](https://www.docker.com/products/docker-hub/)). Please note that the size of our docker container the dataset is about `12GB`, so please prepare sufficient disk space.

```bash
docker pull xingkongwhl/sleuth:latest
docker run -it --privileged --name sleuth xingkongwhl/sleuth:latest /bin/bash	# Don't overlook the '--privileged' option.
```

##### Manually Setup your Environment

We tested our tool Sleuth on `Ubuntu 20.04`. We recommend to install a modern Ubuntu OS, `>= 18.04 && <= 20.04` with `LLVM v12` and `Python 3.8`. Furthermore, Sleuth also relies on `SVF`and `z3`. To build Sleuth yourself, we recommend you continue at [script/INSTALL.md](src/script/INSTALL.md). 

### Quick Start

We integrated the benchmark build commands into the automated scripts. If you want to test a new CVE not in our benchmark, please refer to [script/REDAME.md](src/script/README.md).

1. Preparing the required program and PoC. You need to create a new folder under the `project/program_project` directory to store the CVE's poc (save at [benchmark](benchmark)). Name this folder with the CVE's identifier. For example, CVE-2023-0799 in libtiff : `/path/to/project/libtiff_project/CVE-2023-0799`

2. Build the target program.  (For convenience, using the provided script)

   ```
   cd $SLEUTH_PATH/src/script/run_model
   ./CVE-Year-ID.sh
   ```

3. Run Sleuth.

   ```bash
   cd $SLEUTH_PATH/src/exec
   python autoRun.py CVE-Year-ID [time] [round] SLEUTH		# For example, python autoRun.py CVE-Year-ID 20m 1 SLEUTH
   ```

4. Analysis crash (only run sleuth, don't mind the error message.)

   ```bash
   cd $SLEUTH_PATH/src/exec/crash_analysis
   ./crash_run.sh CVE-Year-ID
   ```

5. Generate evaluation results of new impacts

   ```bash
   cd $SLEUTH_PATH/src/exec/generate_result
   python impact_deal.py CVE-Year-ID
   python count.py
   ```

   The result is save in `$SLEUTH_PATH/Experiment/result`

### Detailed Description

We list the source code structure at [description.md](src/script/description.md), you can get a more detailed description of each component.

### How to reproduce the results of our paper

We compare Sleuth with [AFLplusplus](https://github.com/AFLplusplus/AFLplusplus) and [Evocatio](https://github.com/HexHive/Evocatio).
Since running all test cases would take several weeks, we have saved the logs from these runs to facilitate quick reproduction of the results in our paper. Our logs are saved in [paper/data_zip](paper/data_zip/).

Quickly Reproduce:

- unzip the organized data

  ```bash
  cd $SLEUTH_PATH/src/exec/generate_result
  rm -rf $SLEUTH_PATH/paper/CVE*
  python $SLEUTH_PATH/paper/data_zip/tar.py
  ```

- reproduce result (take approximately 20 minute)

  ```bash
  python paper_result.py
  ```

  The result is save in `$SLEUTH_PATH/Experiment/result`. Each result corresponds to the figures in the paper, please refer to the previous section [description.md](src/script/description.md). Experiment corresponding to Table 5 involved extensive manual analysis, so we are not including it in the automated script.

If you want to manually run all the experimental processes, please refer to [script/README_COMP.md](src/script/README_COMP.md) and [script/README_PATCH.md](src/script/README_PATCH.md).
