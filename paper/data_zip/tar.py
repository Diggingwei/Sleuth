import os
import sys
import tarfile

Sleuth_path = os.getenv("SLEUTH_PATH")

CVE_list = ["CVE-2018-17795", "CVE-2018-12900", "CVE-2020-11895", "CVE-2020-11894", "CVE-2020-6628", "CVE-2019-16705", "CVE-2018-20591", "CVE-2018-8905", "CVE-2018-9009", "CVE-2018-8964", "CVE-2018-7871", "CVE-2021-45078", "CVE-2021-20294", "CVE-2021-20284", "CVE-2020-35493", "CVE-2020-16592", "CVE-2019-20094", "CVE-2019-20024", "CVE-2021-3272", "CVE-2020-27828", "CVE-2018-19543", "CVE-2018-19540", "CVE-2021-3246", "CVE-2020-21676", "CVE-2020-21675", "CVE-2023-1916", "CVE-2023-0799", "CVE-2023-0804", "CVE-2022-3598", "CVE-2020-19143", "CVE-2019-7663", "CVE-2023-30084", "CVE-2023-30083", "CVE-2021-34341", "CVE-2021-34339", "CVE-2021-34338", "CVE-2018-9132", "CVE-2018-7875", "CVE-2022-47673", "CVE-2022-45703", "CVE-2022-4285", "CVE-2020-35448", "CVE-2020-16591", "CVE-2023-31724", "CVE-2023-29582", "CVE-2021-33468", "CVE-2021-33466", "CVE-2021-33465", "CVE-2022-26981", "CVE-2019-16165"]

def create_directories(base_dir):
    os.makedirs(os.path.join(base_dir, "sleuth_crash/crash_final"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "sleuth_crash/fix_crash_final"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "afl_crash/comp_crash_final"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "evo_crash/seed_crash_final"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "crash_example"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "sleuth_crash"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "afl_crash"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "evo_crash"), exist_ok=True)

def extract_files(tar_path, base_dir):
    with tarfile.open(tar_path, "r:gz") as tar:
        for member in tar.getmembers():
            if "crash_final" in member.name and "fix" not in member.name and "comp" not in member.name and "seed" not in member.name:
                target_dir = os.path.join(base_dir, "sleuth_crash/crash_final")
            elif "fix_crash_final" in member.name:
                target_dir = os.path.join(base_dir, "sleuth_crash/fix_crash_final")
            elif "comp_crash_final" in member.name:
                target_dir = os.path.join(base_dir, "afl_crash/comp_crash_final")
            elif "seed_crash_final" in member.name:
                target_dir = os.path.join(base_dir, "evo_crash/seed_crash_final")
            elif "crash_example" in member.name:
                target_dir = os.path.join(base_dir, "crash_example")
            elif "init.txt" in member.name and "fix" not in member.name:
                target_dir = os.path.join(base_dir, "sleuth_crash")
            elif "fix_init.txt" in member.name:
                target_dir = os.path.join(base_dir, "sleuth_crash")
            elif "comp.txt" in member.name:
                target_dir = os.path.join(base_dir, "afl_crash")
            elif "evo.txt" in member.name:
                target_dir = os.path.join(base_dir, "evo_crash")
            else:
                target_dir = base_dir
            if member.isdir():
                continue
            member.name = os.path.basename(member.name)
            tar.extract(member, target_dir)

def main(cve_id):
    tar_file = Sleuth_path + "/paper/data_zip/" + f"{cve_id}.tar.gz"
    base_dir = Sleuth_path + "/paper/" + cve_id

    os.makedirs(base_dir, exist_ok=True)
    create_directories(base_dir)

    extract_files(tar_file, base_dir)

if __name__ == "__main__":

    for cve_id in CVE_list:
        main(cve_id)

