import os
import sys
import shutil
from datetime import datetime
from pathlib import Path

path = sys.argv[1]
path_2 = sys.argv[2]
fileList=os.listdir(path)

parent_dir_path = Path(path).parent
poc_dir = parent_dir_path / 'poc_1'

if poc_dir.exists() and poc_dir.is_file():
    poc_ctime = os.path.getmtime(poc_dir)
    poc_ctime = datetime.fromtimestamp(poc_ctime)
else:
    print(f"The file 'poc_1' does not exist in the directory {parent_dir_path}")

index_line = 0

for i in fileList:

    if i == "README.txt" or "poc" in i:
        continue

    current_file_path = os.path.join(path + '/' + i)

    current_file_ctime = os.path.getmtime(current_file_path)
    current_file_ctime = datetime.fromtimestamp(current_file_ctime)

    time_difference = abs(current_file_ctime - poc_ctime)
    time_difference_ms = int(time_difference.total_seconds() * 1000)
    
    newname = path_2 + os.sep + 'poc' + "_" + str(index_line) + "_" + str(time_difference_ms)
    oldname = path + os.sep + i
    # os.rename(oldname, newname)
    shutil.copy2(oldname, newname)

    index_line += 1
