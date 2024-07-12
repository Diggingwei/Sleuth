import subprocess
import sys
import os
import impact_deal
import count
import severity_score
import time_deal

CVE_list = ["CVE-2018-17795", "CVE-2018-12900", "CVE-2020-11895", "CVE-2020-11894", "CVE-2020-6628", "CVE-2019-16705", "CVE-2018-20591", "CVE-2018-8905", "CVE-2018-9009", "CVE-2018-8964", "CVE-2018-7871", "CVE-2021-45078", "CVE-2021-20294", "CVE-2021-20284", "CVE-2020-35493", "CVE-2020-16592", "CVE-2019-20094", "CVE-2019-20024", "CVE-2021-3272", "CVE-2020-27828", "CVE-2018-19543", "CVE-2018-19540", "CVE-2021-3246", "CVE-2020-21676", "CVE-2020-21675", "CVE-2023-1916", "CVE-2023-0799", "CVE-2023-0804", "CVE-2022-3598", "CVE-2020-19143", "CVE-2019-7663", "CVE-2023-30084", "CVE-2023-30083", "CVE-2021-34341", "CVE-2021-34339", "CVE-2021-34338", "CVE-2018-9132", "CVE-2018-7875", "CVE-2022-47673", "CVE-2022-45703", "CVE-2022-4285", "CVE-2020-35448", "CVE-2020-16591", "CVE-2023-31724", "CVE-2023-29582", "CVE-2021-33468", "CVE-2021-33466", "CVE-2021-33465", "CVE-2022-26981", "CVE-2019-16165"]

Sleuth_path = os.getenv("SLEUTH_PATH")

def get_file(_id, _table):
    with open(_table, 'r') as t:
        lines = t.readlines()
        for line in lines:
            if _id in line:
                s_path = Sleuth_path + line.split('\t')[0]
                f_path = Sleuth_path + line.split('\t')[1]
                return s_path, f_path
        return None, None

def run_script(script_name, args):
    cmd = ["python", script_name] + args
    result = subprocess.run(cmd, capture_output=True, text=True)

def run_script_2(script_name, args, out_file):
    with open(out_file, 'w') as f:
        result = subprocess.run(["python", script_name] + args, stdout=f, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print(f"Error running {script_name}: {result.stderr}")

if __name__ == "__main__":

    vuln_file = Sleuth_path + "/paper/vulnInfo/VulnTable.txt"
    analysis_script = Sleuth_path + '/src/vuln_tool/asan_analysis.py'
    impact_script = Sleuth_path + '/src/exec/generate_result/impact_deal.py'
    count_script = Sleuth_path + '/src/exec/generate_result/count.py'
    severity_script = Sleuth_path + '/src/exec/generate_result/severity_score.py'
    time_script = Sleuth_path + '/src/exec/generate_result/time_deal.py'
    asan_args = []
    # Run asan_analysis.py
    for cve_id in CVE_list:
        vuln_info, vuln_project = get_file(cve_id, vuln_file)
        asan_args.append(vuln_project)
        asan_args = [
            vuln_project,
            vuln_info + '/sleuth_crash/crash_final',
            vuln_info + '/sleuth_crash/init.txt',
            vuln_info + '/afl_crash/comp_crash_final',
            vuln_info + '/afl_crash/comp.txt',
            vuln_info + '/evo_crash/seed_crash_final',
            vuln_info + '/evo_crash/evo.txt',
            vuln_info + '/crash_example',
        ]
        out_file = vuln_info + '/save.txt'  

        run_script_2(analysis_script, asan_args, out_file)


    # Run import_deal.py
    for cve_id in CVE_list:
        impact_args = [cve_id]
        impact_args.append("--paper")
        run_script(impact_script, impact_args)

    # Run count.py
    count_args = ["--paper"]
    run_script(count_script, count_args)
    
    # Run severity_score.py
    run_script(severity_script, count_args)

    # Run time_deal.py
    time_args = [""]
    run_script(time_script, time_args)