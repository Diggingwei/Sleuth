import re
import sys
import os
import json
import argparse
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FuncFormatter
from scipy.interpolate import interp1d
from collections import defaultdict

fixed_CVE_list = ["CVE-2018-17795", "CVE-2018-12900", "CVE-2018-8905", "CVE-2021-45078", "CVE-2021-20294", "CVE-2021-20284", "CVE-2020-35493", "CVE-2020-16592", "CVE-2019-20094", "CVE-2019-20024", "CVE-2021-3272", "CVE-2018-19543", "CVE-2018-19540", "CVE-2020-21676", "CVE-2020-21675", "CVE-2023-0804", "CVE-2022-47673", "CVE-2022-4285", "CVE-2020-35448", "CVE-2020-16591", "CVE-2022-26981"]

def format_func(value, tick_number):
    return f'{int(value)}'

def deal_type(impact_list):
    hofr = 0
    hofw = 0
    uafr = 0
    uafw = 0
    gofr = 0
    gofw = 0
    sof = 0
    wa = 0
    np = 0
    other = 0
    for impact in impact_list:
        if impact == "heap-buffer-overflow@@READ":
            hofr = impact_list[impact]
        elif impact == "heap-buffer-overflow@@WRITE":
            hofw = impact_list[impact]
        elif impact == "heap-use-after-free@@READ":
            uafr = impact_list[impact]
        elif impact == "heap-use-after-free@@WRITE":
            uafw = impact_list[impact]
        elif impact == "global-buffer-overflow@@READ":
            gofr = impact_list[impact]
        elif impact == "global-buffer-overflow@@WRITE":
            gofw = impact_list[impact]
        elif "stack" in impact:
            sof += impact_list[impact]
        elif "wild-address" in impact:
            wa += impact_list[impact]
        elif "null-pointer" in impact:
            np += impact_list[impact]
        else:
            other = other + impact_list[impact]
    data = [hofr, hofw, uafr, uafw, gofr, gofw, sof, wa, np]
    return data

def total_behavior(implit, vuln, collect, result_dir, sleuth_path, _json, _switch, _paper):

    implit_file = os.listdir(implit)
    vuln_file = os.listdir(vuln)

    data_list = []

    new_behavior = 0
    new_behavior_collect = {}
    fixed_new_behavior_collect = {}
    cve_new_behavior = {}

    old_behavior = 0
    old_behavior_collect = {}
    fixed_old_behavior_collect = {}
    cve_old_behavior = {}

    evo_behavior = 0
    evo_behavior_collect = {}
    fixed_evo_behavior_collect = {}
    evo_new_behavior = {}

    y1_total = [0]
    y2_total = [0]
    y3_total = [0]
    n1_total = 0
    n2_total = 0
    n3_total = 0
    x1_total = [0]
    x2_total = [0]
    x3_total = [0]

    new_program = 0

    new_number = 0
    old_number = 0
    evo_number = 0

    total_crash = {}
    total_type = {}

    type_identify = ['HOR', 'HOW', 'UAR', 'UAW', 'SOF', 'GOR', 'GOW', '#N', '#W']

    common_impacts = []
    y1_same = [0]
    y2_same = [0]
    y3_same = [0]
    n1_same = 0
    n2_same = 0
    n3_same = 0
    x1_same = [0]
    x2_same = [0]
    x3_same = [0]


    for v in vuln_file:

        os_file = vuln + "/" + v
        # id = (v.split("compare_vuln_")[-1]).split(".txt")[0]
        id = (v.split("compare_vuln_")[-1]).split(".json")[0]
        symbol = '========'
        new_file = result_dir + "/" + id + ".txt"
        initial_type = collect[id]

        sleuth_impact = {}
        afl_impact = {}
        evo_impact = {}
        result_impact = {}

        #print(v)

        with open(os_file, 'r') as report:
            new_type = 0
            afl_type = 0
            evo_type = 0
            flag = 0
            new_bug = 0
            old_bug = 0
            evo_bug = 0
            new_cve = 0
            old_cve = 0
            evo_cve = 0
            total_crash[id] = []
            total_type[id] = []

            report_json = json.load(report)
            impact_type = report_json["summary"]
            impact_new = report_json["new_sites"]
            impact_afl = report_json["afl_sites"]
            impact_evo = report_json["evo_sites"]
            new_fuzz_type = impact_type["our_fuzz_vuln"]
            afl_fuzz_type = impact_type["afl_vuln"]
            evo_fuzz_type = impact_type["evo_vuln"]

            # total count
            types_0 = set()
            for item in new_fuzz_type["type_num"]:
                if item["type"] in type_identify:
                    types_0.add(item["type"])
                    if item["type"] not in total_type[id]:
                        total_type[id].append(item["type"])
            new_type = len(types_0)

            types_1 = set()
            for item in afl_fuzz_type["type_num"]:
                if item["type"] in type_identify:
                    types_1.add(item["type"])
                    if item["type"] not in total_type[id]:
                        total_type[id].append(item["type"])
            afl_type = len(types_1)

            types_2 = set()
            for item in evo_fuzz_type["type_num"]:
                if item["type"] in type_identify:
                    types_2.add(item["type"])
                    if item["type"] not in total_type[id]:
                        total_type[id].append(item["type"])
            evo_type = len(types_2)

            # single count
            for site in impact_new:
                new_bug += 1
                new_number += 1
                crash_line = site["site"]
                time_hour = site["hours"]
                time_line = site["minutes"]
                if crash_line not in total_crash[id]:
                    total_crash[id].append(crash_line)
                
                now_type = '@@'.join(crash_line.split('@@')[0:2])

                if id in collect:
                    if now_type != "" and now_type != "requested@@unknown" and now_type != "SEGV@@READ":
                        new_behavior += 1
                        flag = 1
                        new_cve += 1
                        x1_total.append(int(time_line))
                        n1_total += 1
                        y1_total.append(n1_total)

                        sleuth_impact[crash_line] = [time_hour, time_line]

                        if now_type in new_behavior_collect:
                            new_behavior_collect[now_type] += 1
                        else:
                            new_behavior_collect[now_type] = 1

                        if _paper and id in fixed_CVE_list:
                            if now_type in fixed_new_behavior_collect:
                                fixed_new_behavior_collect[now_type] += 1
                            else:
                                fixed_new_behavior_collect[now_type] = 1
                        
            cve_new_behavior[id] = [new_bug, new_cve, new_type]



            if flag == 1:
                new_program += 1

            for site in impact_afl:
                old_bug += 1
                old_number += 1
                crash_line = site["site"]
                time_hour = site["hours"]
                time_line = site["minutes"]
                if crash_line not in total_crash[id]:
                    total_crash[id].append(crash_line)
                
                now_type = '@@'.join(crash_line.split('@@')[0:2])

                if id in collect:
                    if now_type != "" and now_type != "requested@@unknown" and now_type != "SEGV@@READ":
                        old_behavior += 1
                        old_cve += 1
                        x2_total.append(int(time_line))
                        n2_total += 1
                        y2_total.append(n2_total)

                        afl_impact[crash_line] = [time_hour, time_line]

                        if now_type in old_behavior_collect:
                            old_behavior_collect[now_type] += 1
                        else:
                            old_behavior_collect[now_type] = 1

                        if _paper and id in fixed_CVE_list:
                            if now_type in fixed_old_behavior_collect:
                                fixed_old_behavior_collect[now_type] += 1
                            else:
                                fixed_old_behavior_collect[now_type] = 1

            cve_old_behavior[id] = [old_bug, old_cve, afl_type]

            for site in impact_evo:
                evo_bug += 1
                evo_number += 1
                crash_line = site["site"]
                time_hour = site["hours"]
                time_line = site["minutes"]
                if crash_line not in total_crash[id]:
                    total_crash[id].append(crash_line)
                
                now_type = '@@'.join(crash_line.split('@@')[0:2])

                if id in collect:
                    if now_type != "" and now_type != "requested@@unknown" and now_type != "SEGV@@READ":
                        evo_behavior += 1
                        evo_cve += 1
                        if int(time_line) < 720:
                            x3_total.append(int(time_line))
                            n3_total += 1
                            y3_total.append(n3_total)

                        evo_impact[crash_line] = [time_hour, time_line]

                        if now_type in evo_behavior_collect:
                            evo_behavior_collect[now_type] += 1
                        else:
                            evo_behavior_collect[now_type] = 1

                        if _paper and id in fixed_CVE_list:
                            if now_type in fixed_evo_behavior_collect:
                                fixed_evo_behavior_collect[now_type] += 1
                            else:
                                fixed_evo_behavior_collect[now_type] = 1

            evo_new_behavior[id] = [evo_bug, evo_cve, evo_type]
    
        for cve_impact in set(list(sleuth_impact.keys()) + list(afl_impact.keys()) + list(evo_impact.keys())):
            result_impact[cve_impact] = [afl_impact.get(cve_impact, ['-'])[0], evo_impact.get(cve_impact, ['-'])[0], sleuth_impact.get(cve_impact, ['-'])[0]]
        with open(new_file, 'w') as f:
            f.write(f"{initial_type}\n\n")
            for key, value in result_impact.items():
                f.write(f"{key}: {value}\n")

        common = set(afl_impact.keys()) & set(sleuth_impact.keys())

        for impact in common:
            if int(sleuth_impact[impact][1]) < 680:
                x1_same.append(int(sleuth_impact[impact][1]))
                n1_same += 1
                y1_same.append(n1_same)
            if int(afl_impact[impact][1]) < 680:
                x2_same.append(int(afl_impact[impact][1]))
                n2_same += 1
                y2_same.append(n2_same)
            
            if impact in evo_impact and int(evo_impact[impact][1]) < 680:
                x3_same.append(int(evo_impact[impact][1]))
                n3_same += 1
                y3_same.append(n3_same)

    x1_same.append(675)
    x2_same.append(675)
    x3_same.append(675)
    y1_same.append(n1_same)
    y2_same.append(n2_same)
    y3_same.append(n3_same)

    x1_same = sorted(x1_same)
    x2_same = sorted(x2_same)
    x3_same = sorted(x3_same)

    fig = plt.figure()

    plt.plot(x1_same, y1_same, color='#483D8B', label ='Sleuth')
    plt.plot(x2_same, y2_same, linestyle='-.', color='#8B0000', label='afl-cexp')
    #plt.plot(x3_same, y3_same, linestyle='--', color='darkgoldenrod', label='Evocatio')

    plt.ylim(bottom=240)

    plt.legend()

    plt.xlabel('Fuzzing Time(minutes)')
    plt.ylabel('Number of New Bug Impacts')

    plt.savefig(sleuth_path + "/Experiment/result/SameImpact_Overtime.png")

    plt.clf()

    print(str(new_program), " has new behavior")

    impact_type = ['HOR', 'HOW', 'UAR', 'UAW', 'GOR', 'GOW', 'SOF', '#W', '#N']

    if _paper:
        sleuth_data = deal_type(fixed_new_behavior_collect)
        afl_data = deal_type(fixed_old_behavior_collect)
        evocatio_data = deal_type(fixed_evo_behavior_collect)
    else:
        sleuth_data = deal_type(new_behavior_collect)
        afl_data = deal_type(old_behavior_collect)
        evocatio_data = deal_type(evo_behavior_collect)

    x = np.arange(len(impact_type))
    width = 0.2

    plt.bar(x - width, sleuth_data, width=width, color='#483D8B', edgecolor='white', label='Sleuth')
    plt.bar(x, afl_data, width=width, color='#8B0000', edgecolor='white', label='afl-cexp')
    plt.bar(x + width, evocatio_data, width=width, color='darkgoldenrod', edgecolor='white', label='Evocatio')

    plt.xlabel('Type of Bug Impact')
    plt.gca().yaxis.set_major_formatter(FuncFormatter(format_func))
    plt.ylabel('Number of New Bug Impact')

    plt.xticks(x, impact_type)

    plt.legend()

    plt.tight_layout()

    plt.savefig(sleuth_path + "/Experiment/result/Overall_NewBugImpact.png")

    plt.clf()
    
    x1_total.append(720)
    x2_total.append(720)
    x3_total.append(720)
    y1_total.append(n1_total)
    y2_total.append(n2_total)
    y3_total.append(n3_total)

    x1_total = sorted(x1_total)
    x2_total = sorted(x2_total)
    x3_total = sorted(x3_total)

    fig = plt.figure()

    plt.plot(x1_total, y1_total, color='#483D8B', label ='Sleuth')
    plt.plot(x2_total, y2_total, linestyle='-.', color='#8B0000', label='afl-cexp')
    plt.plot(x3_total, y3_total, linestyle='--', color='darkgoldenrod', label='Evocatio')

    plt.legend()

    plt.xlabel('Fuzzing Time(minutes)')
    plt.ylabel('Number of New Bug Impacts')

    plt.savefig(sleuth_path + "/Experiment/result/NewImpact_Overtime.png")

    cve_list = []
    for cve in cve_new_behavior:
        cve_list.append(cve)

    print("sleuth behavior number: ", new_behavior)
    print("sleuth total number: ", new_number)
    for t in new_behavior_collect:
        print(t + ":" + str(new_behavior_collect[t]))
    for cve in cve_new_behavior:
        print(cve + ":" + str(cve_new_behavior[cve][0]) + " " + str(cve_new_behavior[cve][1]) + " " + str(cve_new_behavior[cve][2]))
    print('========')
    print("afl behavior number: ", old_behavior)
    print("afl total number: ", old_number)
    for o in old_behavior_collect:
        print(o + ":" + str(old_behavior_collect[o]))
    for cve in cve_old_behavior:
        print(cve + ":" + str(cve_old_behavior[cve][0]) + " " + str(cve_old_behavior[cve][1]) + " " + str(cve_old_behavior[cve][2]))

    print('========')
    print("evocatio behavior number: ", evo_behavior)
    print("evo total number: ", evo_number)
    for e in evo_behavior_collect:
        print(e + ":" + str(evo_behavior_collect[e]))
    for cve in evo_new_behavior:
        print(cve + ":" + str(evo_new_behavior[cve][0]) + " " + str(evo_new_behavior[cve][1]) + " " + str(evo_new_behavior[cve][2]))

    print('========')
    print("all bug: ")
    all_number = 0
    for b in total_crash:
        print(b + ":" + str(len(total_crash[b])))
        all_number += len(total_crash[b])
    print("all bug number: ", all_number)

    for cve in cve_list:
        if cve == "CVE-2019-16165":
            print(total_type[cve])
        data_item = {"CVE_ID": cve, "Switch": _switch[cve], "Sleuth": {"New Impact": str(cve_new_behavior[cve][0]), "Type": str(cve_new_behavior[cve][2])}, "afl-cexp": {"New Impact": str(cve_old_behavior[cve][0]), "Type": str(cve_old_behavior[cve][2])}, "Evocatio": {"New Impact": str(evo_new_behavior[cve][0]), "Type": str(evo_new_behavior[cve][2])}, "Total": {"New Impact": str(len(total_crash[cve])), "Type": str(len(total_type[cve]))}}
        data_list.append(data_item)
    return data_list


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script to analyze bug impacts.")

    parser.add_argument('--paper', action='store_true', help='Reproduce the paper results. (default: 0, if provided: 1)')
    args = parser.parse_args()
    paper_value = 1 if args.paper else 0

    Sleuth_path = os.getenv("SLEUTH_PATH")
    path_dir = Sleuth_path + "/Experiment/result"
    implit = path_dir + "/Unique_Impact"
    vuln = path_dir + "/Unique_Crash_Compare"
    vuln_type = Sleuth_path + "/src/vulnInfo/vulnType.txt"
    new_result = path_dir + "/NewImpact_Efficiency"
    json_path = path_dir + "/New_Impact_Table-2.json"
    switch_path = Sleuth_path + "/src/vulnInfo/switch.txt"

    if paper_value:
        vuln_type = Sleuth_path + "/paper/vulnInfo/vulnType.txt"
        switch_path = Sleuth_path + "/paper/vulnInfo/switch.txt"

    initVuln_collect = {}
    switch_collect = {}

    if not os.path.exists(new_result):
        os.makedirs(new_result)

    with open(switch_path, 'r') as report:
        for line in report:
            cve_id = line.split(' ')[0]
            num = line.split(' ')[1].strip()
            if cve_id not in switch_collect:
                switch_collect[cve_id] = num

    with open(vuln_type, 'r') as report:
        for line in report:
            cve_id = line.split(' ')[0]
            type = ("@@".join(line.split(' ')[1:3])).strip()
            if type not in initVuln_collect:
                initVuln_collect[cve_id] = type

    data_list = total_behavior(implit, vuln, initVuln_collect, new_result, Sleuth_path, json_path, switch_collect, paper_value)

    with open(json_path, "w") as json_file:
        json.dump(data_list, json_file, indent=4)