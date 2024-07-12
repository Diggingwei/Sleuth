import os
import pandas as pd
import xlwt
import re

def main():
    workbook = xlwt.Workbook()
    sheet = workbook.add_sheet('Sheet1')
    Sleuth_path = os.getenv("SLEUTH_PATH")
    output_file = Sleuth_path + '/Experiment/result/NewImpact_Efficiency.xls'


    headers = ['CVE ID', 'Initial Bug Impact', 'Discovered New Bug Impacts', 'afl-cexp', 'Evocatio', 'Sleuth']

    for i, header in enumerate(headers):
        sheet.write(0, i, header)

    folder_path = Sleuth_path + '/Experiment/result/NewImpact_Efficiency'
    files = os.listdir(folder_path)

    row = 1
    for file_name in files:
        cve_id = os.path.splitext(file_name)[0]
        with open(os.path.join(folder_path, file_name), 'r') as file:
            lines = file.readlines()

            initial_impact = lines[0].strip()
            impact_times = [x.strip() for x in lines[2:]]
            

            for j, time in enumerate(impact_times):
                new_impact = time.split(': ')[0]
                time_set = time.split(': ')[1]
                items = re.findall(r"'(.*?)'", time_set)
                sheet.write(row, 0, cve_id)
                sheet.write(row, 1, initial_impact)
                _type = new_impact.split('@@')[0]
                _access = new_impact.split('@@')[1]
                _line = (new_impact.split('@@')[2]).split('/')[-1]
                if _type == 'null-pointer':
                    sheet.write(row, 2, 'null-pointer-dereference at ' + _line)
                elif _type == 'wild-address':
                    sheet.write(row, 2, 'wild-address-read at ' + _line)
                elif 'stack-' in _type:
                    sheet.write(row, 2, 'stack-buffer-overflow at ' + _line)
                else:
                    sheet.write(row, 2, _type + ' ' + _access + ' at ' + _line)
                if items[0] == '0.00':
                    sheet.write(row, 3, '<0.01')
                else:
                    sheet.write(row, 3, items[0])
                if items[1] == '0.00':
                    sheet.write(row, 4, '<0.01')
                else:
                    sheet.write(row, 4, items[1])
                if items[2] == '0.00':
                    sheet.write(row, 5, '<0.01')
                else:
                    sheet.write(row, 5, items[2])
                row += 1
    workbook.save(output_file)


if __name__ == "__main__":
    main()