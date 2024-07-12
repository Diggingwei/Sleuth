# How to test a new CVE using Sleuth
- Set the environment variables
    ```bash
    source $SLEUTH_PATH/src/evn/instrument.sh
    ``` 
- Build the target program which contains the new CVE.
- Create a new folder to store the new CVE's poc. Name this folder with the CVE identifier. For example, `/path/to/CVE-2023-0799`.
- Add a new line to `$SLEUTH_PATH/src/vulnInfo/VulnTable.txt`, which collects the information required to reproduce the CVE. The form is `[/path/to/CVE-ID  /path/to/program    target binary   parameters]`. Four argvs need to be customized manually, and the argvs are separated by `\t`. Don't forget the `\t` and replace the input to `@@` in `parameters`.
- Execute the poc to generate the initial impact information.
    ```bash
    cd $SLEUTH_PATH/src/vuln_tool
    ./run.sh CVE-ID
    ```
- Use static analysis to compile the target file where CVE triggers into `bitcode` and save the memory relevant graph in `target.json`. (We will optimize this part in the future)
    ```bash
    cd /path/to/target_program
    $SLEUTH_PATH/ddgAnalysis/build/tools/dataflow-cc -emit-llvm -(required compilation options) -g -O0 -S -o target_file.bc target_file.c
    $SLEUTH_PATH/ddgAnalysis/build/tools/static-dua --ander target_file.bc --out=$SLEUTH_PATH/src/vulnInfo/target.json
    ```
- Recompile target program using `Sleuth`.
    ```bash
    cd /path/to/target_program
    make clean
    DDG_INSTR=1 AFL_LLVM_INSTRUMENT=classic make
    ```
- Copy the initial poc to an input directory, then run Sleuth
    ```bash
    $SLEUTH_PATH/Sleuth/afl-fuzz -m none -C -i /path/to/input/directory -o /path/to/output -k /path/to/initial/poc -- /path/to/target/program @@
    ```