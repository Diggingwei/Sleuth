import subprocess
import multiprocessing
import time
import sys
import os
import argparse

_path = os.getenv('SLEUTH_PATH')

def run_command(command):
    subprocess.run(command, shell=True)

def main():
    parser = argparse.ArgumentParser(description="Run afl-fuzz in parallel")
    parser.add_argument("VULN", type=str, help="CVE identifier. Example: CVE-2023-0799")
    parser.add_argument("TIME", type=str, help="Runtime. Example: 12s(sound), 12m(minute), 12h(hour)")
    parser.add_argument("ROUND", type=int, help="Number of rounds to run. Example: 5")
    parser.add_argument("MODE", type=str, help="Use which tools. Example: 1.SLEUTH: run sleuth, 2.AFL: run aflplusplus, 3.EVOCATIO: run evocatio, 4.COMP: run all tools")
    args = parser.parse_args()

    VULN = sys.argv[1]
    TIME = sys.argv[2]
    ROUND = int(sys.argv[3])
    MODE = sys.argv[4]
    TABLE = os.path.join(_path, 'src/vulnInfo/VulnTable.txt')

    if not VULN:
        print("please input CVE")
        sys.exit(0)

    project_path = ""
    info_path = ""
    param = ""

    with open(TABLE, 'r') as file:
        for line in file:
            if VULN in line:
                fields = line.strip().split('\t')
                project_path = fields[1]
                info_path = fields[0]
                param = fields[3]
                break
        
    if not project_path or not info_path or not param:
        print(f"{VULN} not found in {TABLE}")
        sys.exit(0)

    PROJECT = _path + project_path
    INFO = _path + info_path
    PARAM = param

    INITPOC = os.path.join(INFO, 'poc')
    SRC = os.path.join(PROJECT, f'fuzz_{VULN}')
    COMPSRC = os.path.join(PROJECT, f'comp_fuzz_{VULN}')
    EVOSRC = os.path.join(PROJECT, f'evo_fuzz_{VULN}')
    INFILE = os.path.join(SRC, 'in')
    OUTFILE = os.path.join(SRC, 'out_')
    COMPINFILE = os.path.join(COMPSRC, 'in')
    COMPOUTFILE = os.path.join(COMPSRC, 'out_')
    SEEDINFILE = os.path.join(INFO, 'evo_crash/seeds')
    EVOOUTFILE = os.path.join(EVOSRC, 'out_')

    EXE = None
    COMPEXE = None
    EVOEXE = None

    for root, dirs, files in os.walk(SRC):
        for file in files:
            if file.endswith("_cov"):
                EXE = os.path.join(root, file)

    for root, dirs, files in os.walk(COMPSRC):
        for file in files:
            if file.endswith("_cov"):
                COMPEXE = os.path.join(root, file)

    for root, dirs, files in os.walk(EVOSRC):
        for file in files:
            if file.endswith("_cov"):
                EVOEXE = os.path.join(root, file)

    SLEUTH = os.path.join(_path, 'Sleuth/afl-fuzz')
    AFLplusplus = os.path.join(_path, 'AFLplusplus/afl-fuzz')
    EVOCATIO = os.path.join(_path, 'Evocatio/bug-severity-AFLplusplus/afl-fuzz')

    for i in range(1, ROUND + 1):
        sleuth_cmd = f"screen -S {VULN}-{i} -dm bash -c \"timeout {TIME} {SLEUTH} -m none -C -i {INFILE} -o {OUTFILE}{i} -k {INITPOC} -- {EXE} {PARAM}\""
        afl_cmd = f"screen -S comp_{VULN}-{i} -dm bash -c \"timeout {TIME} {AFLplusplus} -m none -C -i {COMPINFILE} -o {COMPOUTFILE}{i} -- {COMPEXE} {PARAM}\""
        evocatio_cmd = f"screen -S evo_{VULN}-{i} -dm bash -c \"timeout {TIME} {EVOCATIO} -m none -C -i {SEEDINFILE} -o {EVOOUTFILE}{i} -k {INFO}/evo_crash/poc_1 -- {EVOEXE} {PARAM}\""

        if MODE == 'SLEUTH':
            print(sleuth_cmd)
            run_command(sleuth_cmd)
            print("==================================")
        elif MODE == 'AFL':
            print(afl_cmd)
            run_command(afl_cmd)
            print("==================================")
        elif MODE == 'EVOCATIO':
            print(evocatio_cmd)
            run_command(evocatio_cmd)
            print("==================================")
        elif MODE == 'COMP':
            print(sleuth_cmd)
            run_command(sleuth_cmd)
            print("==================================")
            print(afl_cmd)
            run_command(afl_cmd)
            print("==================================")
            print(evocatio_cmd)
            run_command(evocatio_cmd)
            print("==================================")
        else:
            print("see autoRun.py -h")
            break

if __name__ == "__main__":
    main()


