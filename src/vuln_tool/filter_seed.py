import re
import sys
import os
import re
import shutil

def filter_site(_path, _key):
    file_list = []
    filenames = os.listdir(_path)
    for file in filenames:
        os_file = _path + "/" + file
        with open(os_file, 'r') as report:
            _txt = report.read()
            if "wild-address" in _key[0]:
                if "SEGV" in _txt and _key[2] in _txt and "address points to the zero page" not in _txt and "dereference of a high value address" not in _txt:
                    file_list.append(file)
            elif "null-pointer" in _key[0]:
                if "SEGV" in _txt and _key[2] in _txt and ("address points to the zero page" in _txt or "dereference of a high value address" in _txt):
                    file_list.append(file)
            elif "stack-overflow" in _key[0] and "unknown" in _key[1]:
                if _key[0] in _txt and _key[2] in _txt:
                    file_list.append(file)
            elif "unknown_crash" not in _key[0]:
                if _key[0] in _txt and _key[1] in _txt and _key[2] in _txt:
                    file_list.append(file)

    return file_list



def extract_string_after_first_slash(input_string):
    index = input_string.find('/')
    if index != -1:
        return input_string[index + 1:]
    else:
        return input_string

def copy_file_to_folder(file_path, folder_path):
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    file_name = os.path.basename(file_path)
    destination_path = os.path.join(folder_path, file_name)

    shutil.copy(file_path, destination_path)

if __name__ == "__main__":
    file_1 = sys.argv[1]
    Sleuth_path = os.getenv("SLEUTH_PATH")
    the_file = Sleuth_path + '/' + file_1
    target_file = the_file + '/requir_seed'
    sleuth_asan = the_file + '/save.txt'
    afl_asan = the_file + '/save.txt'
    evo_asan = the_file + '/save.txt'
    sleuth_key = []
    afl_key = []
    evo_key = []
    sleuth_read = ""
    afl_read = ""
    evo_read = ""
    sleuth_crash = the_file + '/sleuth_crash/crash_final'
    afl_crash = the_file + '/afl_crash/comp_crash_final'
    evo_crash = the_file + '/evo_crash/seed_crash_final'
    sleuth_path = the_file + '/sleuth_crash/init.txt'
    afl_path = the_file + '/afl_crash/comp.txt'
    evo_path = the_file + '/evo_crash/evo.txt'
    sleuth_seed = target_file + '/sleuth_seeds'
    afl_seed = target_file + '/afl_seeds'
    evo_seed = target_file + '/evo_seeds'

    with open(sleuth_asan, 'r') as report_1:
        file_txt = report_1.read()
        symbol_pos_1 = file_txt.find('=====1=====')
        symbol_pos_2 = file_txt.find('=====2=====')
        symbol_pos_3 = file_txt.find('=====3=====')
        symbol_pos_4 = file_txt.find('=====4=====')
        sleuth_result = file_txt[symbol_pos_1:symbol_pos_2]
        afl_result = file_txt[symbol_pos_2:symbol_pos_3]
        evo_result = file_txt[symbol_pos_3:symbol_pos_4]

        for line in sleuth_result.split('\n'):
            if '@@' in line:
                vuln_info = line.split('@@')
                vuln_type = vuln_info[0]
                vuln_access = vuln_info[1]
                vuln_key = extract_string_after_first_slash(vuln_info[2])
                vuln_time = vuln_info[3]
                sleuth_use = [vuln_type, vuln_access, vuln_key, vuln_time]
                sleuth_key.append(sleuth_use)
        for line in afl_result.split('\n'):
            if '@@' in line:
                vuln_info = line.split('@@')
                vuln_type = vuln_info[0]
                vuln_access = vuln_info[1]
                vuln_key = extract_string_after_first_slash(vuln_info[2])
                vuln_time = vuln_info[3]
                if vuln_type != "" and vuln_access != "" and vuln_key != "":
                    afl_use = [vuln_type, vuln_access, vuln_key, vuln_time]
                    afl_key.append(afl_use)
        for line in evo_result.split('\n'):
            if '@@' in line:
                vuln_info = line.split('@@')
                vuln_type = vuln_info[0]
                vuln_access = vuln_info[1]
                vuln_key = extract_string_after_first_slash(vuln_info[2])
                vuln_time = vuln_info[3]
                if vuln_type != "" and vuln_access != "" and vuln_key != "":
                    evo_use = [vuln_type, vuln_access, vuln_key, vuln_time]
                    evo_key.append(evo_use)
    '''
    with open(evo_asan, 'r') as report_2:
        file_txt = report_2.read()
        for line in file_txt.split('\n'):
            if '@@' in line:
                vuln_info = line.split('@@')
                vuln_type = vuln_info[0]
                vuln_access = vuln_info[1]
                vuln_key = extract_string_after_first_slash(vuln_info[2])
                vuln_time = vuln_info[3]
                if vuln_type != "" and vuln_access != "" and vuln_key != "":
                    evo_use = [vuln_type, vuln_access, vuln_key, vuln_time]
                    evo_key.append(evo_use)
    '''

    with open(sleuth_path, 'r') as report_3:
        sleuth_read = report_3.read()
    
    with open(afl_path, 'r') as report_4:
        afl_read = report_4.read()

    with open(evo_path, 'r') as report_5:
        evo_read = report_5.read()

    for key in sleuth_key:
        sleuth_list = filter_site(sleuth_crash, key)

        for line in sleuth_read.split('\n'):
            if line:
                _name = line.split(' ')[0]
                _file = line.split(' ')[1]
                if _name in sleuth_list and _file.split('_')[-1] == key[3]:
                    if os.path.exists(_file):
                        copy_file_to_folder(_file, sleuth_seed)
                        break

    for key in afl_key:
        afl_list = filter_site(afl_crash, key)
        for line in afl_read.split('\n'):
            if line:
                _name = line.split(' ')[0]
                _file = line.split(' ')[1]
                if _name in afl_list and _file.split('_')[-1] == key[3]:
                    if os.path.exists(_file):
                        copy_file_to_folder(_file, afl_seed)
                        break
    for key in evo_key:
        evo_list = filter_site(evo_crash, key)
        for line in evo_read.split('\n'):
            if line:
                _name = line.split(' ')[0]
                _file = line.split(' ')[1]
                if _name in evo_list and _file.split('_')[-1] == key[3]:
                    if os.path.exists(_file):
                        copy_file_to_folder(_file, evo_seed)
                        break

    