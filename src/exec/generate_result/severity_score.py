import sys
import os
import argparse
import math
import re
import json

class ImpactDetail:
    def __init__(self, _initType):
        self.init_type = _initType

class SeverityScore:
    def __init__(self, impact_txt_dir):
        self.impact_dir = impact_txt_dir
        self.initVuln_collect = {}
        self.initCVSS_score = {}

    def _load_files(self):
        files = []
        for file_name in os.listdir(self.impact_dir):
            file_path = os.path.join(self.impact_dir, file_name)
            if os.path.isfile(file_path):
                files.append(file_path)
        return files

    def _calculate_score(self, _type_dict, _flag):
        score_total = 0
        keys_1 = ['SOF', 'GOR', 'GOW']
        value_1 = 0
        score_1 = 0
        num_1 = 0
        keys_2 = ['HOW', 'UAW']
        value_2 = 0
        score_2 = 0
        num_2 = 0
        keys_3 = ['HOR', 'UAR']
        value_3 = 0
        score_3 = 0
        num_3 = 0
        keys_4 = ['N', 'W']
        value_4 = 0
        score_4 = 0
        num_4 = 0
        for key in keys_1:
            if key in _type_dict:
                value_1 += _type_dict[key]
                num_1 += 1
        for key in keys_2:
            if key in _type_dict:
                value_2 += _type_dict[key]
                num_2 += 1
        for key in keys_3:
            if key in _type_dict:
                value_3 += _type_dict[key]
                num_3 += 1
        for key in keys_4:
            if key in _type_dict:
                value_4 += _type_dict[key]
                num_4 += 1

        if _flag != 1 and value_1 != 0:
            score_1 = 2.5 + 1/(2 + math.exp(-value_1 / 15))
        elif _flag == 1:
            score_1 = 1/(2 + math.exp(-(1 + value_1) / 15))
        if num_1 == 1 and score_1 != 0:
            score_1 -= 0.2
        
        if _flag != 2 and value_2 != 0:
            score_2 = 2 + 1/(2 + math.exp(-value_2 / 2))
        elif _flag == 2:
            score_2 = 1/(2 + math.exp(-(1 + value_2) / 2))
        if num_2 == 1 and score_2 != 0:
            score_2 -= 0.2

        if _flag != 3 and value_3 != 0:
            score_3 = 1.5 + 1/(2 + math.exp(-value_3 / 15))
        elif _flag == 3:
            score_3 = 1/(2 + math.exp(-(1 + value_3) / 15))
        if num_3 == 1 and score_3 != 0:
            score_3 -= 0.2

        if _flag != 4 and value_4 != 0:
            score_4 = 1 + 1/(2 + math.exp(-value_4 / 15))
        elif _flag == 4:
            score_4 = 1/(2 + math.exp(-(1 + value_4) / 15))
        if num_4 == 1 and score_4 != 0:
            score_4 -= 0.2

        score_total = score_1 + score_2 + score_3 + score_4

        return round(score_total, 1)


    def get_severity_score(self, file):
        score_item = {}
        impact_string = ""
        cve_id = ""
        y1_score_base = 0
        y2_score_base = 0
        base_flag = 0
        match = re.search(r'CVE-\d{4,}-\d+', file)
        if match:
            cve_id = match.group(0)

        with open(file, 'r') as report:
            report_json = json.load(report)
            new_fuzz_type = report_json["summary"]["our_fuzz_vuln"]
            impact_num = new_fuzz_type["count"]
            impact_string = new_fuzz_type["type_num"]

        type_dict = {}
        for string in impact_string:
            type_dict[string["type"]] = string["num"]
        
        if "stack-buffer-overflow" in self.initVuln_collect[cve_id] or "stack_overflow" in self.initVuln_collect[cve_id] or "global-buffer-overflow" in self.initVuln_collect[cve_id]:
            base_flag = 1
            y1_score_base = 2.5
            #y1_score_base = 3
        elif "heap-buffer-overflow" in self.initVuln_collect[cve_id] or "heap-use-after-free" in self.initVuln_collect[cve_id]:
            #y1_score_base = 3
            y1_score_base = 1.5
            base_flag = 3
            if "WRITE" in self.initVuln_collect[cve_id]:
                y1_score_base += 0.5
                base_flag = 2
        elif "null" in self.initVuln_collect[cve_id] or "wild" in self.initVuln_collect[cve_id]:
            #y1_score_base = 2.5
            y1_score_base = 1
            base_flag = 4


        y2_score_base = self._calculate_score(type_dict, base_flag)

        final_score_base = 0.5 + y1_score_base + y2_score_base

        score_item = {"CVE_ID": cve_id, "Initial Impact": self.initVuln_collect[cve_id], "New Impacts": type_dict, "Sleuth_score": str(final_score_base), "CVSS_score": {"Impact": self.initCVSS_score[cve_id][0], "Base": self.initCVSS_score[cve_id][1]}}
        return score_item



def main():
    parser = argparse.ArgumentParser(description="Script to analyze bug impacts.")

    parser.add_argument('--paper', action='store_true', help='Reproduce the paper results. (default: 0, if provided: 1)')
    args = parser.parse_args()
    paper_value = 1 if args.paper else 0

    Sleuth_path = os.getenv("SLEUTH_PATH")
    path_dir = Sleuth_path + "/Experiment/result/Unique_Crash_Compare"
    vuln_type = Sleuth_path + "/src/vulnInfo/vulnType.txt"
    score_path = Sleuth_path + "/src/vulnInfo/score.txt"
    json_path = Sleuth_path + "/Experiment/result/Severity_score_Table-4.json"

    if paper_value:
        vuln_type = Sleuth_path + "/paper/vulnInfo/vulnType.txt"
        score_path = Sleuth_path + "/paper/vulnInfo/score.txt"

    impact_score = SeverityScore(path_dir)
    files = impact_score._load_files()
    data_list = []

    with open(vuln_type, 'r') as report:
        for line in report:
            cve_id = line.split(' ')[0]
            type = ("@@".join(line.split(' ')[1:3])).strip()
            if cve_id not in impact_score.initVuln_collect:
                impact_score.initVuln_collect[cve_id] = type

    with open(score_path, 'r') as report:
        for line in report:
            cve_id = line.split(' ')[0]
            score_1 = line.split(' ')[1]
            score_2 = line.split(' ')[2].strip()
            if cve_id not in impact_score.initCVSS_score:
                impact_score.initCVSS_score[cve_id] = [score_1, score_2]


    for file in files:
        data_list.append(impact_score.get_severity_score(file))

    with open(json_path, "w") as json_file:
        json.dump(data_list, json_file, indent=4)


if __name__ == "__main__":
    main()

