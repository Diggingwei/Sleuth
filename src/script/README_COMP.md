# Comparison test

- Download AFLplusplus at https://github.com/AFLplusplus/AFLplusplus, Evocatio at https://github.com/HexHive/Evocatio, save these projects at $SLEUTH_PATH, and the build is like Sleuth
- We write the use example of AFLplusplus in the Sleuth script, you can see in $SLEUTH_PATH/src/script/run_model. To compile the project, follow these steps:
    ```bash
    cd $SLEUTH_PATH/src/script/run_model
    ./CVE-ID.sh
    ```
- We write the use example of Evocatio in $SLEUTH_PATH/src/script/evo_model. To compile projects with Evocatio, use the following command.
    ```bash
    cd $SLEUTH_PATH/src/script/evo_model
    ./seed-ID.sh
    ```
- Run the comparison experiment. In our paper, we set each test case to run for `12h` and conduct `5 rounds`, you can run `autoRun.py` to get the execution command and run it automatically.
    ```bash
    python autoRun.py CVE-ID 12h 5 COMP
    ```
    Run `python autoRun.py -h` to learn about other parameters. Additionally, use `screen -list` to display the running processes, `screen -r process-id` to view the fuzzing process
- After the fuzz testing completes, run the crash analysis script.
    ```bash
    cd $SLEUTH_PATH/src/exec/crash_analysis
    screen -S CVE-ID -dm bash -c "./crash_run.sh CVE-ID"
    ```
- Generate evaluation results for newly discovered impacts. 
    ```bash
    cd ../generate_result
    python impact_deal.py CVE-ID
    python count.py
    ```
    The impacts of each CVE discovery is saved in `$SLEUTH_PATH/Experiment/result/Unique_Crash_Compare`.

    The impacts discovered results by Sleuth, afl-cexp and Evocatio are save in `$SLEUTH_PATH/Experiment/result/New_Impact_Table-2.json`.

- Generate evaluation results for the Efficiency of discovering new impacts.
    ```bash
    python time_deal.py
    ```
    The results are saved in `$SLEUTH_PATH/Experiment/result/output.xls`

- Generate evaluation results for the severity scores.
    ```bash
    python severity_score.py
    ```
    The results are saved in `$SLEUTH_PATH/Experiment/result/Severity_score_Table-4.json`