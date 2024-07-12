import re
import sys
import os
import re

file_list = []
initial_seed = 121

def filter_site(_path, _key):
    filenames = os.listdir(_path)
    for file in filenames:
        os_file = _path + "/" + file
        with open(os_file, 'r') as report:
            for line in report:
                if _key in line:
                    now_seed = int(file.split('.')[2])
                    final_seed = int((now_seed - initial_seed)/2)
                    if file not in file_list:
                        print(file + " " + str(final_seed))
                        file_list.append(file)
                

if __name__ == "__main__":
    path = sys.argv[1]
    key_string = sys.argv[2]
    #path_txt = sys.argv[3]
    filter_site(path, key_string)
    '''
    with open(path_txt, 'r') as report:
        for line in report:
            for string in file_list:
                if string in line:
                    print(line)
    '''

	
