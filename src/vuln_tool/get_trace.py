from fileinput import close
from itertools import count
import re
import sys
import os

class vuln:
    def __init__(self, v_type, v_opt, v_bit, v_site, v_alloc, v_free, trace_1, trace_2, trace_3):
        self.type = v_type
        self.opt = v_opt
        self.bit = v_bit
        self.site = v_site
        self.alloc = v_alloc
        self.free = v_free
        self.site_trace = trace_1
        self.alloc_trace = trace_2
        self.free_trace = trace_3

    def creat_trace(self, text, number):
        if 'location=<null>' not in text:
            _info = text.strip()[1:-1].split(', ')
            _info_loc = _info[-1].split('location=')[1]
            _info_func = _info[1].split('function=')[1]


            if number == 1 and len(_info_loc.split(':')) > 2:
                #self.site_trace += _info_func + ' ' + _info_loc.rsplit(':',1)[0] + '\n'
                self.site_trace += _info_func + ' ' + _info_loc.split(':')[0] + ':' + _info_loc.split(':')[1] + ':' + _info_loc.split(':')[2] + '\n'
            elif number == 2 and len(_info_loc.split(':')) > 2:
                #self.alloc_trace += _info_func + ' ' + _info_loc.rsplit(':',1)[0] + '\n'
                self.alloc_trace += _info_func + ' ' + _info_loc.split(':')[0] + ':' + _info_loc.split(':')[1] + ':' + _info_loc.split(':')[2] + '\n'
            elif number == 3 and len(_info_loc.split(':')) > 2:
                #self.free_trace += _info_func + ' ' + _info_loc.rsplit(':',1)[0] + '\n'
                self.free_trace += _info_func + ' ' + _info_loc.split(':')[0] + ':' + _info_loc.split(':')[1] + ':' + _info_loc.split(':')[2] + '\n'


def get_info(_line):
    if len(sys.argv) == 3:
        target_vuln_file = sys.argv[2]      # we identify the vuln file manified
    else:
        target_vuln_file = ""
    count_site = 0
    site_line = []
    wild_flag = 0
    v_type = ""
    v_opt = ""
    v_bit = ""
    v_site = ""
    v_alloc= ""
    v_free = ""
    trace_1 = ""
    trace_2 = ""
    trace_3 = ""
    vex = vuln(v_type, v_opt, v_bit, v_site, v_alloc, v_free, trace_1, trace_2, trace_3)
    # vuln information
    for l in _line:
        if "SUMMARY" in l and "-buffer-overflow" not in l and "heap-use-after-free" not in l and "SEGV" not in l and "FPE " not in l and "stack-overflow" not in l:
            vex = None
            return vex
        if "wild pointer" in l:
            '''
            vex = None
            return vex
            '''
            wild_flag = 1

    for l in _line:
        l_seg = l.strip().split(' ')
        if "SUMMARY" in l:
            vex.type = l_seg[2]
        elif l_seg[0] == "READ" or l_seg[0] == "WRITE":
            vex.opt = l_seg[0]
            re1 = r'size(.*?)thread'
            reResult_1 = re.findall(re1, l)
            vex.bit = reResult_1[0].strip()
        elif l.strip() == "":
            site_line.append(count_site)
        count_site += 1
    # vuln type information
    if "-buffer-overflow" in vex.type:
        for i, rows in enumerate(_line):
            # vuln context
            if i in range(0, site_line[0]):
                if "frame=" in rows:
                    vex.creat_trace(rows, 1)

            # alloc context
            if wild_flag == 0 and vex.type == "heap-buffer-overflow":
                if i in range(site_line[0], site_line[1]):
                    if "frame=" in rows:
                        vex.creat_trace(rows, 2)
        if wild_flag == 0:
            if len(vex.alloc_trace.strip().split('\n')) > 1:
                vex.alloc += vex.alloc_trace.strip().split('\n')[1]
            else:
                vex.alloc += vex.alloc_trace.strip().split('\n')[0]
        site_trace_list = vex.site_trace.strip().split('\n')
        for site_trace in site_trace_list:
            if "/asan/" not in site_trace and "memcpy" not in site_trace.split(' ')[0] and "memset" not in site_trace.split(' ')[0] and ".c" in site_trace and target_vuln_file in site_trace:
                vex.site += site_trace
                break
        '''
        if "/asan/" not in vex.site_trace.strip().split('\n')[0]:
            vex.site += vex.site_trace.strip().split('\n')[0]
        else:
            vex.site += vex.site_trace.strip().split('\n')[1]
        '''

    if vex.type == "heap-use-after-free":
        for i, rows in enumerate(_line):
            # vuln context
            if i in range(0, site_line[0]):
                if "frame=" in rows:
                    vex.creat_trace(rows, 1)
            # free context
            if i in range(site_line[0], site_line[1]):
                if "frame=" in rows:
                    vex.creat_trace(rows, 3)
            # alloc context
            if i in range(site_line[1], site_line[2]):
                if "frame=" in rows:
                    vex.creat_trace(rows, 2)
        if len(vex.alloc_trace.strip().split('\n')) > 1:
            vex.alloc += vex.alloc_trace.strip().split('\n')[1]
        if len(vex.free_trace.strip().split('\n')) > 1:
            vex.free += vex.free_trace.strip().split('\n')[1]
        site_trace_list = vex.site_trace.strip().split('\n')
        for site_trace in site_trace_list:
            if "/asan/" not in site_trace and "memcpy" not in site_trace.split(' ')[0] and "memset" not in site_trace.split(' ')[0] and '.c' in site_trace and target_vuln_file in site_trace:
                vex.site += site_trace
                break
        '''
        if "/asan/" not in vex.site_trace.strip().split('\n')[0]:
            vex.site += vex.site_trace.strip().split('\n')[0]
        else:
            vex.site += vex.site_trace.strip().split('\n')[1]
        '''
    
    if vex.type == "SEGV":
        for i, rows in enumerate(_line):
            #vuln context
            if i in range(0, site_line[0]):
                if "frame=" in rows:
                    vex.creat_trace(rows, 1)
                if "READ " in rows:
                    vex.opt = "READ"
                elif "WRITE " in rows:
                    vex.opt = "WRITE"
            
            #alloc context
            if wild_flag == 0:
                if len(site_line) > 2:
                    if "frame=" in rows:
                        vex.creat_trace(rows, 1)
        if wild_flag == 0 and len(site_line) > 2:
            vex.alloc += vex.alloc_trace.strip().split('\n')[1]
        site_trace_list = vex.site_trace.strip().split('\n')
        for site_trace in site_trace_list:
            if "/asan/" not in site_trace and "memcpy" not in site_trace.split(' ')[0] and "memset" not in site_trace.split(' ')[0] and '.c' in site_trace and target_vuln_file in site_trace:
                vex.site += site_trace
                break
        '''
        if "/asan/" not in vex.site_trace.strip().split('\n')[0]:
            vex.site += vex.site_trace.strip().split('\n')[0]
        else:
            vex.site += vex.site_trace.strip().split('\n')[1]
        '''
    if vex.type == "FPE":
        for i, rows in enumerate(_line):
            if "frame=" in rows:
                vex.creat_trace(rows, 1)
            if "READ " in rows:
                vex.opt = "READ"
            elif "WRITE " in rows:
                vex.opt = "WRITE"
        site_trace_list = vex.site_trace.strip().split('\n')
        for site_trace in site_trace_list:
            if "/asan/" not in site_trace and "memcpy" not in site_trace.split(' ')[0] and "memset" not in site_trace.split(' ')[0] and '.c' in site_trace and target_vuln_file in site_trace:
                vex.site += site_trace
                break
    if vex.type == "stack-overflow":
        for i, rows in enumerate(_line):
            if "frame=" in rows:
                rows = rows.strip()
                vex.creat_trace(rows, 1)
            if "READ " in rows:
                vex.opt = "READ"
            elif "WRITE " in rows:
                vex.opt = "WRITE"
        site_trace_list = vex.site_trace.strip().split('\n')
        for site_trace in site_trace_list:
            if "/asan/" not in site_trace and "memcpy" not in site_trace.split(' ')[0] and "memset" not in site_trace.split(' ')[0] and '.c' in site_trace and target_vuln_file in site_trace:
                vex.site += site_trace
                break
        
    '''
    if vex.type == "double-free":
        for i, rows in enumerate(_line):
            # vuln context
            if i in range(0, site_line[0]):
                if "frame=" in rows:
                    vex.creat_trace(rows, 1)
            # free context
            if i in range(site_line[0], site_line[1]):
                if "frame=" in rows:
                    vex.creat_trace(rows, 3)
            # alloc context
            if i in range(site_line[1], site_line[2]):
                if "frame=" in rows:
                    vex.creat_trace(rows, 2)
        vex.alloc += vex.alloc_trace.strip().split('\n')[1]
        vex.free += vex.free_trace.strip().split('\n')[1]
        vex.site += vex.site_trace.strip().split('\n')[1]
    '''
    return vex


def get_calls():
    
    if len(sys.argv) == 1:
        print("%s report"%sys.argv[0])
    
    count_phase = 1
    phase_line = []

    vex_list = []

    with open(sys.argv[1], 'r') as report:
        # locate phase
        for line in report:
            if line.strip() == '=================================================================':
                phase_line.append(count_phase)
            count_phase += 1      
        
        line_count = 0
        for phase in phase_line:
            report.seek(0, 0)
            if line_count != len(phase_line) - 1:
                line = report.readlines()[phase:phase_line[line_count + 1]-1]
                vex_id = get_info(line)
                if vex_id != None:
                    vex_list.append(vex_id)

            else:
                line = report.readlines()[phase:]
                vex_id = get_info(line)
                if vex_id != None:
                    vex_list.append(vex_id)

            line_count += 1
    
    return vex_list

if __name__ == "__main__":

    outs = get_calls()

    dir_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    file_1 = sys.argv[1] + "_trace.txt"
    file_2 = sys.argv[1] + "_info.txt"
    file_3 = dir_path + "/vulnInfo/PoC_in.txt"

    f_1 = open(file_1, "w")
    f_2 = open(file_2, "w")
    f_3 = open(file_3, "w")
    for v in outs:
        real_site = os.path.normpath(v.site)
        '''
        if '/./' in v.site:
            real_site = v.site.replace("/./", "/")
        else:
            real_site = v.site
        '''
        print(v.type)
        print(v.opt)
        print(v.bit)
        print(real_site)
        print(v.alloc)
        print(v.free)
        f_1.write(v.site_trace + '\n')
        
        f_2.write("==type== " + v.type + '\n')
        if("-buffer-overflow" in v.type):
            f_2.write("==opt== " + v.opt + '\n' + "==bit== " + v.bit + '\n' + "==alloc== " + v.alloc + '\n' + "==site== " + real_site + '\n\n')
        if("stack-overflow" in v.type):
            f_2.write("==opt== " + v.opt + '\n' + "==bit== " + v.bit + '\n' + "==alloc== " + v.alloc + '\n' + "==site== " + real_site + '\n\n')
        if(v.type == "heap-use-after-free"):
            f_2.write("==opt== " + v.opt + '\n' + "==bit== " + v.bit + '\n' + "==alloc== " + v.alloc + '\n' + "==free== " + v.free + '\n' + "==site== " + real_site + '\n\n')
        if(v.type == "SEGV"):
            f_2.write("==opt== " + v.opt + '\n' + "==bit== " + v.bit + '\n' + "==alloc== " + v.alloc + '\n' + "==site== " + real_site + '\n\n')
        if(v.type == "FPE"):
            f_2.write("==opt== " + v.opt + '\n' + "==bit== " + v.bit + '\n' + "==alloc== " + v.alloc + '\n' + "==site== " + real_site + '\n\n')
    
    f_3.write(os.path.abspath(file_2) + '\n')

    f_1.close()
    f_2.close()
    f_3.close()
