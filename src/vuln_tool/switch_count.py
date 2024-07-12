import os
import re
import sys

total_switch_sum = 0
folder_count = 0

path = sys.argv[1]
output_filename = sys.argv[2]
cve_name = sys.argv[3]

def update_average_switch_data(_cve, _average):
    updated_data = False

    with open(output_filename, 'r') as input_file:
        lines = input_file.readlines()

    with open(output_filename, 'w') as output_file:
        for line in lines:
            if line.startswith(f"{cve_name} "):
                output_file.write(f"{cve_name} {average_switch}\n")
                updated_data = True
            else:
                output_file.write(line)

        if not updated_data:
            output_file.write(f"{cve_name} {average_switch}\n")

for folder_name in os.listdir(path):
    if folder_name.startswith("out") and os.path.isdir(path + '/' + folder_name):
        folder_count += 1
        folder_path = os.path.join(path, folder_name)
        switch_debug_file = os.path.join(folder_path, "default/switch_debug")
        if os.path.exists(switch_debug_file):
            with open(switch_debug_file, 'r') as f:
                last_line = f.readlines()[-1]
                match = re.search(r'switch number is (\d+)', last_line)
                if match:
                    switch_number = int(match.group(1))
                    total_switch_sum += switch_number

average_switch = total_switch_sum / folder_count

update_average_switch_data(cve_name, average_switch)



