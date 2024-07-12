import os
import sys

path = sys.argv[1]
fileList=os.listdir(path)

for i in fileList:

    if i.find("time:") == -1 or i.find("orig:") != -1:
    # if i.find("time:") == -1:
        continue

    start_index = i.find("id:") + len("id:")
    end_index = i.find(",", start_index)
    index_line = i[start_index : end_index]

    start_time = i.find("time:") + len("time:")
    end_time = i.find(",", start_time)
    time_line = i[start_time : end_time]

    newname = path + os.sep + 'poc' + "_" + index_line + "_" + time_line
    oldname = path + os.sep + i
    os.rename(oldname, newname)
