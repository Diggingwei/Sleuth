import matplotlib.pyplot as plt
import os
import sys
import json
import argparse

class VulnSite:
    def __init__(self, type, time, count):
        self._type = type
        self._time = time
        self._count = count

class VulnName:
    def __init__(self):
        self.collect_txt = {}

    def add_collect(self, call_trace, _vuln_site):
        self.collect_txt[call_trace] = _vuln_site

class TypeNumber:
    def __init__(self):
        self.collect_type = {}
    def add_type_number(self, _type):
        if _type not in self.collect_type:
            self.collect_type[_type] = 1
        else:
            self.collect_type[_type] += 1

class Vulnpare:
    def __init__(self, id, path, graph_dir, site_dir, vuln_dir):
        self.one_file = ""
        self.graph_file = ""
        self.site_file = ""
        self.vuln_file = ""
        self._graph_dir = graph_dir
        self._site_dir = site_dir
        self._vuln_dir = vuln_dir
        self._id = id
        self.collect_site = {}
        self.collect_site_2 = {}
        self.collect_site_3 = {}
        self.sleuth_path = path

    def add_oneway(self, str):
        self.one_file = str

    def add_saveGraph(self, str):
        self.graph_file = str
    
    def add_saveSite(self, str):
        self.site_file = str

    def add_saveVuln(self, str):
        self.vuln_file = str

    def max_xlable(self, m, n):
        if m > n:
            return m
        else:
            return n
    
    def checkDir(self):
        check_graph_dir = self.sleuth_path + self._graph_dir
        check_site_dir = self.sleuth_path + self._site_dir
        check_vuln_dir = self.sleuth_path + self._vuln_dir
        if not os.path.exists(check_graph_dir):
            os.makedirs(check_graph_dir)
            print(f"Folder '{check_graph_dir}' created")
        else:
            print(f"Folder '{check_graph_dir}' exists")
        
        if not os.path.exists(check_site_dir):
            os.makedirs(check_site_dir)
            print(f"Folder '{check_site_dir}' created")
        else:
            print(f"Folder '{check_site_dir}' exists")

        if not os.path.exists(check_vuln_dir):
            os.makedirs(check_vuln_dir)
            print(f"Folder '{check_vuln_dir}' created")
        else:
            print(f"Folder '{check_vuln_dir}' exists")

    def result_redection(self, fuzz):

        vuln_real = VulnName()
        vuln_false = VulnName()
        fuzz_line = ""
        for line in fuzz.split('\n'):
            if '@@' in line:
                vuln_info = line.split('@@')
                vuln_type = vuln_info[0]
                # vuln_name = '@@'.join(vuln_info[1:3])
                vuln_name = '@@'.join(vuln_info[0:3])
                vuln_time = vuln_info[3]
                vuln_count = vuln_info[4]
                now_site = VulnSite(vuln_type, vuln_time, vuln_count)
                if vuln_type == "FPE" or vuln_type == "requested" or vuln_type == "allocator" or vuln_type == "mem-leak" or vuln_type == "unknown-crash":
                    continue

                vuln_real.add_collect(vuln_name, now_site)
                '''
                if vuln_type == "unknown-crash":
                    vuln_name = 'READ@@' + vuln_name.split('@@')[-1]        # add by wei
                    if vuln_name in vuln_false.collect_txt:
                        if int(vuln_false.collect_txt[vuln_name]._time) > int(vuln_time):
                            vuln_false.collect_txt[vuln_name]._time = vuln_time
                    else:
                        vuln_false.add_collect(vuln_name, now_site) 
                else:
                    if vuln_name in vuln_real.collect_txt:
                        if int(vuln_real.collect_txt[vuln_name]._time) > int(vuln_time):
                            vuln_real.collect_txt[vuln_name]._time = vuln_time
                    else:
                        vuln_real.add_collect(vuln_name, now_site)
                '''
        
        '''
        for false_name in vuln_false.collect_txt:
            if false_name in vuln_real.collect_txt:
                if int(vuln_real.collect_txt[false_name]._time) > int(vuln_false.collect_txt[false_name]._time):
                    vuln_real.collect_txt[false_name]._time = vuln_false.collect_txt[false_name]._time
            else:
                vuln_real.add_collect(false_name, vuln_false.collect_txt[false_name])
        '''
        
        for name in vuln_real.collect_txt:
            # past_list = [vuln_real.collect_txt[name]._type, name, vuln_real.collect_txt[name]._time, vuln_real.collect_txt[name]._count]
            past_list = [name, vuln_real.collect_txt[name]._time, vuln_real.collect_txt[name]._count]
            one_line = '@@'.join(past_list)
            fuzz_line += one_line + '\n'

        #print(fuzz_line)
        return fuzz_line

    def time_compare(self, newfuzz, aflfuzz, evofuzz):

        y1 = [0]
        y2 = [0]
        x1 = [0]
        x2 = [0]
        y3 = [0]
        x3 = [0]

        n = 0
        m = 0
        k = 0
        for line in newfuzz.split('\n'):
            if '@@' in line:
                time_value = int(line.split('@@')[-2])/60000
                x1.append(n)
                y1.append(time_value)
                n = n + 1
                x1.append(n)
                y1.append(time_value)
        x1.append(n)
        y1.append(720)
        
        for line in aflfuzz.split('\n'):
            if '@@' in line:
                time_value = int(line.split('@@')[-2])/60000
                x2.append(m)
                y2.append(time_value)
                m = m + 1
                x2.append(m)
                y2.append(time_value)
        x2.append(m)
        y2.append(720)

        for line in evofuzz.split('\n'):
            if '@@' in line:
                time_value = int(line.split('@@')[-2])/60000
                x3.append(k)
                y3.append(time_value)
                k = k + 1
                x3.append(k)
                y3.append(time_value)
        x3.append(k)
        y3.append(720)

        #print(y1)
        #print(x1)
        #print(y2)
        #print(x2)

        y1_sort = sorted(y1)
        y2_sort = sorted(y2)
        y3_sort = sorted(y3)
        fig, ax = plt.subplots()

        ax.plot(y1_sort, x1, linewidth=1, label='sleuth')
        ax.plot(y2_sort, x2, linewidth=1, label='afl++')
        ax.plot(y3_sort, x3, linewidth=1, label='evocatio')
        ax.set_title('Time of finding new crash points in ' + self._id)
        ax.set_xlabel('time')
        ax.set_ylabel('crash number')
        # y_max = max(max(y1_sort), max(y2_sort)) + 1
        x_max = max(max(x1), max(x2), max(x3)) + 1
        space = 1
        if x_max >= 10:
            space = round(x_max / 10)
        
        plt.xticks(range(0, 800, 100))
        plt.yticks(range(0, x_max, space))
        plt.legend()
        plt.savefig(self.graph_file) 

    def get_typeName(self, _name_complete):
        index = _name_complete.find('@@', _name_complete.find('@@') + 2)
        _name = _name_complete[:index]
        if _name == "heap-buffer-overflow@@READ":
            return "HOR"
        elif _name == "heap-buffer-overflow@@WRITE":
            return "HOW"
        elif _name == "heap-use-after-free@@READ":
            return "UAR"
        elif _name == "heap-use-after-free@@WRITE":
            return "UAW"
        elif "wild-address" in _name:
            return "#W"
        elif "null-pointer" in _name:
            return "#N"
        elif "stack-overflow" in _name or "stack-buffer-overflow" in _name:
            return "SOF"
        elif _name == "global-buffer-overflow@@READ":
            return "GOR"
        elif _name == "global-buffer-overflow@@WRITE":
            return "GOW"
        elif "allocator" in _name:
            return "#A"
        else:
            return "#O"

    def get_typeNum(self, _type_collect):
        combine = []
        sorted_type = dict(sorted(_type_collect.items()))
        for _type in sorted_type:
            combine.append({
                "type": _type,
                "num": sorted_type[_type]
            })
        return combine

    def get_file(self, _id, _table):
        with open(_table, 'r') as t:
            lines = t.readlines()
            for line in lines:
                if _id in line:
                    s_path = (line.split('\t')[1]).split('/')
                    f_path = self.sleuth_path + '/'.join(s_path[:-1]) + '/' + _id + '/save.txt'
                    # evo_path = self.sleuth_path + '/'.join(s_path[:-1]) + '/' + _id + '/evo_save.txt'
                    graph_path = self.sleuth_path + self._graph_dir + '/compare_plat_' + _id + '.png'
                    site_path = self.sleuth_path + self._site_dir + '/compare_site_' + _id + '.txt'
                    vuln_path = self.sleuth_path + self._vuln_dir + '/compare_vuln_' + _id + '.json'
                    self.add_saveGraph(graph_path)
                    self.add_saveSite(site_path)
                    self.add_saveVuln(vuln_path)
                    # return f_path, evo_path
                    return f_path
                    break
            return None

    def site_compare(self, newfuzz, aflfuzz, evofuzz):
        site_listNew = []
        site_listAfl = []
        site_listEvo = []
        TypeCollect_1 = TypeNumber()
        TypeCollect_2 = TypeNumber()
        TypeCollect_3 = TypeNumber()
        sleuth_count = 0
        afl_count = 0
        evo_count = 0
        data = {
            "new_sites": [],
            "afl_sites": [],
            "evo_sites": [],
            "summary": {}
        }

        for line in newfuzz.split('\n'):
            if '@@' in line:
                t_site = line.split('@@')
                f_site = '@@'.join(t_site[:-2])
                site_time = t_site[-2]
                if f_site not in self.collect_site:
                    self.collect_site[f_site] = site_time
                site_listNew.append(f_site)
        for line in aflfuzz.split('\n'):
            if '@@' in line:
                t_site = line.split('@@')
                f_site = '@@'.join(t_site[:-2])
                if f_site not in self.collect_site_2:
                    self.collect_site_2[f_site] = t_site[-2]
                site_listAfl.append(f_site)
        for line in evofuzz.split('\n'):
            if '@@' in line:
                t_site = line.split('@@')
                f_site = '@@'.join(t_site[:-2])
                if f_site not in self.collect_site_3:
                    self.collect_site_3[f_site] = t_site[-2]
                site_listEvo.append(f_site)


        differ_site = list(set(site_listNew).difference(set(site_listAfl)))

        with open(self.site_file, 'w') as file:
            for s in differ_site:
                s_time = "{:.2f}".format(int(self.collect_site[s])/1000/60/60)
                m_time = round(int(self.collect_site[s])/1000/60)
                file.write(s + " " + str(s_time) + " " +str(m_time) + '\n')

        for new in site_listNew:
            bri_name = self.get_typeName(new)
            if bri_name == '#O' or bri_name == '#A':
                continue
            TypeCollect_1.add_type_number(bri_name)
            data["new_sites"].append({
                "site": new,
                "hours": "{:.2f}".format(int(self.collect_site[new])/3600000),
                "minutes": round(int(self.collect_site[new])/60000)
            })
            sleuth_count += 1
        
        for afl in site_listAfl:
            bri_name = self.get_typeName(afl)
            if bri_name == '#O' or bri_name == '#A':
                continue
            TypeCollect_2.add_type_number(bri_name)
            data["afl_sites"].append({
                "site": afl,
                "hours": "{:.2f}".format(int(self.collect_site_2[afl]) / 3600000),
                "minutes": round(int(self.collect_site_2[afl]) / 60000)
            })
            afl_count += 1

        for evo in site_listEvo:
            bri_name = self.get_typeName(evo)
            if bri_name == '#O' or bri_name == '#A':
                continue
            TypeCollect_3.add_type_number(bri_name)
            data["evo_sites"].append({
                "site": evo,
                "hours": "{:.2f}".format(int(self.collect_site_3[evo]) / 3600000),
                "minutes": round(int(self.collect_site_3[evo]) / 60000)
            })
            evo_count += 1

        data["summary"] = {
            "our_fuzz_vuln": {
                "count": sleuth_count,
                "type_num": self.get_typeNum(TypeCollect_1.collect_type)
            },
            "afl_vuln": {
                "count": afl_count,
                "type_num": self.get_typeNum(TypeCollect_2.collect_type)
            },
            "evo_vuln": {
                "count": evo_count,
                "type_num": self.get_typeNum(TypeCollect_3.collect_type)
            }
        }

        with open(self.vuln_file, 'w') as file:
            json.dump(data, file, indent=4)

    def analysis_result(self, cve_id, table_file):
        # target_file, evo_file = self.get_file(cve_id, table_file)
        target_file = self.get_file(cve_id, table_file)
        # evo_result = ""
        if target_file:
            print(target_file)
        else:
            print("no this file")
            return
        '''
        try:
            with open(evo_file, 'r') as file_2:
                file_txt_2 = file_2.read()
                evo_result = file_txt_2
        except FileNotFoundError:
            print(evo_file + ' no exist')
        '''
        
        try:
            with open(target_file, 'r') as file:
                file_txt = file.read()
                symbol_pos_1 = file_txt.find('=====1=====')
                symbol_pos_2 = file_txt.find('=====2=====')
                symbol_pos_3 = file_txt.find('=====3=====')
                symbol_pos_4 = file_txt.find('=====4=====')
                netfuzz_result = file_txt[symbol_pos_1:symbol_pos_2]
                afl_result = file_txt[symbol_pos_2:symbol_pos_3]
                evo_result = file_txt[symbol_pos_3:symbol_pos_4]
                new_evofuzz_result = self.result_redection(evo_result)
                new_netfuzz_result = self.result_redection(netfuzz_result)
                new_afl_result = self.result_redection(afl_result)
                self.time_compare(new_netfuzz_result, new_afl_result, new_evofuzz_result)
                self.site_compare(new_netfuzz_result, new_afl_result, new_evofuzz_result)


        except FileNotFoundError:
            print(target_file + ' not exist')
            return

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Script to analyze bug impacts.")

    parser.add_argument("VULN", type=str, help="CVE identifier. Example: CVE-2023-0799")
    parser.add_argument('--paper', action='store_true', help='Reproduce the paper results. (default: 0, if provided: 1)')

    args = parser.parse_args()
    paper_value = 1 if args.paper else 0

    file_1 = sys.argv[1]

    Sleuth_path = os.getenv("SLEUTH_PATH")

    file_2 = Sleuth_path + "/src/vulnInfo/VulnTable.txt"
    if paper_value :
        file_2 = Sleuth_path + "/paper/vulnInfo/VulnTable.txt"

    graph_dir = "/Experiment/result/GraphOfTime"
    site_dir = "/Experiment/result/Unique_Impact"
    vuln_dir = "/Experiment/result/Unique_Crash_Compare"

    vuln_result = Vulnpare(file_1, Sleuth_path, graph_dir, site_dir, vuln_dir)
    vuln_result.checkDir()
    vuln_result.analysis_result(file_1, file_2)
