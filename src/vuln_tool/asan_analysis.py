import re
import sys
import os
import re

class vulnInfo:
    def __init__(self, time):
        self.site_num = 0
        self.time = time
        self.addr_list = []
    def _add_site(self, num):
        self.site_num = self.site_num + num
    def _give_time(self, time):
        self.time = self.time if int(self.time) < int(time) else time 
    def _add_addr(self, addr):
        (self.addr_list).append(addr)

class vulnList:
    def __init__(self):
        self.project_name = ""
        self.collect_txt = {}
        self.time_txt = {}
        self.current_name = ""
        self.initpoc_name = ""
        self.initpoc_trace = ""

    def change_file_name(self, name):
        self.current_name = name
        
    def add_addr(self, addr):
        self.addr_list.append(addr)

    def extract_string(self, s):
        parts = s.split(':')

        if len(parts) <= 2:
            return s.replace("USE->", "")
        return (':'.join(parts[:2])).replace("USE->", "")

    def exclude_col(self, s):
        parts = s.split(':')

        if len(parts) <= 2:
            return s
        return ':'.join(parts[:2])
    
    def extract_asan_callstack(self, err_msg, max_site = 1):
        patt = '\[frame=[0-9]+, function=.*, location=.*]'
        match_list = re.findall(patt, err_msg)
        site_list = []
        for m in match_list:
            site_line_init = m[m.find('location=') + 9: m.find(']')]
            site_line = site_line_init.split(self.project_name)[-1]
            if site_line != '<null>' and '/asan/' not in site_line:
                site_list.append(site_line)
        if len(site_list) > max_site:
            site_list = site_list[:max_site]
        return site_list
        
    # --------------------------------------------------------------------------------------------
    def update_new_asan(self, err_msg):
        """Update Sanitizer in ASan mode"""
        baccess = 'unknown'
        lpos = err_msg.find('ERROR: AddressSanitizer: ')
        if lpos == -1 and err_msg.find('ERROR: LeakSanitizer: '):
            btype = 'mem-leak'
        else:
            btype = err_msg[lpos + 25:][:err_msg[lpos + 25:].find(' ')]
            # patt = '\[frame=[0-9]+, function=.*]' #, location=.*\
            patt = '\[frame=[0-9]+, function=.*, location=.*]'
        if btype == 'heap-use-after-free':
            # first divide error message
            free_pos = err_msg.find('freed by thread')
            alloc_pos = err_msg.find('previously allocated by')
            use_msg = err_msg[:free_pos]
            free_msg = err_msg[free_pos : alloc_pos]
            alloc_msg = err_msg[alloc_pos:]
            # use 
            stack_trace = 'USE->' + '->'.join(self.extract_asan_callstack(use_msg, 1)[::-1])
            # free, skip free
            # stack_trace += ', FREE:' + '->'.join(self.extract_asan_callstack(free_msg, 2)[1:])
            # alloc, skip alloc
            # stack_trace += ', ALLOC:' + '->'.join(self.extract_asan_callstack(alloc_msg, 2)[1:])
        elif btype == 'stack-overflow':
            stack_trace =  '->'.join(self.extract_asan_callstack(err_msg)[::-1])
        else:
            # match_list = re.findall(patt, err_msg)
            # if len(match_list) > 5:
            #   match_list = match_list[:5]
            # # stack_trace = ':'.join(match_list)
            # stack_trace = ''
            # for m in match_list:
            #   stack_trace += m[m.find('function=') + 9: m.find(']')]
            #   stack_trace += ' -> '
            stack_trace =  '->'.join(self.extract_asan_callstack(err_msg, 1)[::-1])
 
        if (err_msg.find('READ of size ') != -1 or err_msg.find('READ memory access') != -1) and btype != 'SEGV':
            baccess = 'READ'
        elif err_msg.find('WRITE of size') != -1 or err_msg.find('WRITE memory access') != -1 and btype != 'SEGV':
            baccess = 'WRITE'

        stack_trace = os.path.normpath(stack_trace)
        # print(self.exclude_col(stack_trace), self.initpoc_trace)
        if (btype == 'SEGV' or btype == 'stack-overflow' or btype == 'unknown-crash') and self.exclude_col(stack_trace) in self.initpoc_trace:
            return

        if (err_msg.find('address points to the zero page.') != -1 or err_msg.find('dereference of a high value address') != -1 or err_msg.find('READ memory access') == -1) and btype == 'SEGV':
            btype = 'null-pointer'
        elif btype == 'SEGV':
            btype = 'wild-address'

        type_stack_trace = btype + '@@' + baccess + '@@' + self.exclude_col(stack_trace)
        type_stack_name = btype + '@@' + baccess
        # print(type_stack_trace, self.initpoc_name)
        if type_stack_name == self.initpoc_name and self.extract_string(stack_trace) in self.initpoc_trace:
            return

        patt = '\.* of size .* at .* thread'
        match_line_list = re.findall(patt, err_msg)
        if match_line_list:
            match_line = match_line_list[0]
            re1 = r'size(.*?)at'
            re2 = r'at(.*?)thread'
            reResult_1 = re.findall(re1, match_line)[0].strip()
            reResult_2 = re.findall(re2, match_line)[0].strip()
            reFinal = reResult_1 + ":" + reResult_2
        else:
            reFinal = "unknown"

        # print(self.current_name, match_line)

        # if type_stack_trace not in self.collect_txt and '->' in type_stack_trace:
        if type_stack_trace not in self.collect_txt and ':' in type_stack_trace:
            self.collect_txt[type_stack_trace] = vulnInfo(self.time_txt[self.current_name])
            if reFinal not in (self.collect_txt[type_stack_trace]).addr_list:
                (self.collect_txt[type_stack_trace])._add_addr(reFinal)
            
        elif type_stack_trace in self.collect_txt:
            self.collect_txt[type_stack_trace]._add_site(1) 
            self.collect_txt[type_stack_trace]._give_time(self.time_txt[self.current_name])
            if reFinal not in (self.collect_txt[type_stack_trace]).addr_list:
                (self.collect_txt[type_stack_trace])._add_addr(reFinal)
        return

    def analysis_program(self, project_name, result_path, result_txt, init_txt):
        self.project_name = project_name
        self.initpoc_name = init_txt[0] + '@@' + init_txt[1]
        self.initpoc_trace = self.exclude_col(init_txt[2].split(self.project_name)[-1])

        try :
            with open(result_txt, 'r') as report_0:
                for line in report_0:
                    asan_result = line.split(' ')[0]
                    poc_name = line.split(' ')[1].strip()
                    #start_index = poc_name.find("time:") + len("time:")
                    #end_index = poc_name.find(",", start_index)
                    #time_0 = poc_name[start_index : end_index]
                    time_0 = poc_name.split('_')[-1].strip()
                    if "README.txt" in time_0:
                        continue
                    if asan_result not in self.time_txt:
                        self.time_txt[asan_result] = time_0
        except FileNotFoundError:
            print("file is not exist")
            return
        
        filenames = os.listdir(result_path)
        for file in filenames:
            if file not in self.time_txt:
                continue
            os_file = result_path + "/" + file
            self.change_file_name(file)
            with open(os_file, 'r') as report:
                report_txt = report.read()
                segement_symbol = '==' + file.split('.')[-1] + '==ERROR'
                report_list = report_txt.split(segement_symbol)
                for txt in report_list[1:]:
                    reset_txt = segement_symbol + txt
                    self.update_new_asan(reset_txt)
        return

def analysis_initial(initial_path):
    initpoc_name = ""
    initpoc_type = ""
    initpoc_opt = ""
    filenames = os.listdir(initial_path)
    for file in filenames:
        if "_info.txt" in file:
            os_file = initial_path + "/" + file
            with open(os_file, 'r') as report_init:
                for line in report_init:
                    if "==type==" in line:
                        initpoc_type = line.split(' ')[1].strip()
                    if "==opt==" in line:
                        initpoc_opt = line.split(' ')[1].strip()
                    if "==site==" in line:
                        initpoc_name = line.split(' ')[2].strip()
                        break
    initpoc = [initpoc_type, initpoc_opt, initpoc_name]
    return initpoc



if __name__ == "__main__":
    project_name = sys.argv[1]
    path1 = sys.argv[2]
    txt1 = sys.argv[3]
    path2 = sys.argv[4]
    txt2 = sys.argv[5]
    path3 = sys.argv[6]
    txt3 = sys.argv[7]
    path0 = sys.argv[8]

    init_poc = analysis_initial(path0)

    TestBench = vulnList()
    TestBench.analysis_program(project_name, path1, txt1, init_poc)

    TestBench_2 = vulnList()
    TestBench_2.analysis_program(project_name, path2, txt2, init_poc)

    TestBench_3 = vulnList()
    TestBench_3.analysis_program(project_name, path3, txt3, init_poc)

    init_list = []
    comp_list = []
    evo_list = []
    address_number_1 = 0
    address_number_2 = 0
    address_number_3 = 0

    print("=====1=====")
    for line in TestBench.collect_txt:
        init_list.append(line)
        time = TestBench.collect_txt[line].time
        addr_num = str(len(TestBench.collect_txt[line].addr_list))
        address_number_1 = address_number_1 + int(addr_num)
        print(line + "@@" + time + "@@" + addr_num)

    print("=====2=====")
    for line in TestBench_2.collect_txt:
        comp_list.append(line)
        time = TestBench_2.collect_txt[line].time
        addr_num = str(len(TestBench_2.collect_txt[line].addr_list))
        address_number_2 = address_number_2 + int(addr_num)
        print(line + "@@" + time + "@@" + addr_num)

    print("=====3=====")
    for line in TestBench_3.collect_txt:
        evo_list.append(line)
        time = TestBench_3.collect_txt[line].time
        addr_num = str(len(TestBench_3.collect_txt[line].addr_list))
        address_number_3 = address_number_3 + int(addr_num)
        print(line + "@@" + time + "@@" + addr_num)

    # comp_num = len(list(set(init_list).difference(set(comp_list))))
    print("=====4=====")
    print ("vuln site1:" + str(len(init_list)))
    print ("address site1:" + str(address_number_1))
    print ("vuln site2:" + str(len(comp_list)))
    print ("address site2:" + str(address_number_2))
    print ("vuln site3:" + str(len(evo_list)))
    print ("address site3:" + str(address_number_3))
    # print ("comp vuln:" + str(comp_num))
