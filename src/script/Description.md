## Code Structure

We list the program directories and some of their files which can be used by artifact evaluations as follows.

- ./Sleuth : The folder storing the source code of our instrument and bug impacts exploration fuzzing tool. 
- ./ddgAnalysis : The folder storing the source code of our static analyzer. 
- ./src : The folder containing the scripts of evaluation.
  - evn/ : Compiling environment.
  - script/ : The directory to run all the experimental setups.
  - exec/ : The directory of result analysis scripts.
    - crash_analysis/ : The directory of scripts for integrating crash results.
    - generate_result/ : The directory of scripts to generate the corresponding tables/figures in the paper.
    - fix_analysis/ : The directory of scripts for integrating patch testing results.
    - autoRun.py : The scripts for automated fuzzing of each test case.
  - vuln_tool/ : The folder of some analysis components.
  - vulnInfo/ : The folder where the preset and processed data is saved.
- ./paper : Data to reproduce our paper's results and the experiment data.
  - data_zip : Data logs to reproduce.
  - result : Paper's experiment data.
  - seeds : PoCs with new impacts.
- ./benchmark : Test cases of our benchmark.
- ./Experiment : The folder where the evaluation results are saved.
  - GraphOfTime/ : The folder where the comparison of the time to discover new impacts are saved.
  - Unique_Impact/ : The folder where the differential impacts discovered by Sleuth are saved.
  - Unique_Crash_Compare/ : The folder where the impacts discovered by Sleuth, afl-cexp and Evocatio are saved.
  - New_Impact_Table-2.json : The results corresponding to Table 2 in the paper.
  - Overall_NewBugImpact.png : The results corresponding to Figure 4 in the paper. (You can test only the highlighted CVEs in Table 2 to reproduce the results in the paper). 
  - NewImpact_Overtime.png : The results corresponding to Figure 5(a) in the paper.
  - SameImpact_Overtime.png : The results corresponding to Figure 5(b) in the paper.
  - NewImpact_Efficiency.xls : The results corresponding to Table 3 in the paper.
  - Severity_score_Table-4.json : The results corresponding to Table 4 in the paper.