# Patch complete validation

- We write the fix example in $SLEUTH_PATH/src/script/fix_model. To compile projects, use the following command.
    ```bash
    cd $SLEUTH_PATH/src/exec/fix_model
    ./fix_CVE-ID.sh
    ```
- Run the crash analysis script to test the completeness of the patch.
    ```bash
    cd $SLEUTH_PATH/src/exec/fix_analysis
    screen -S CVE-ID -dm bash -c "./fix_crash_run.sh CVE-ID"
    ```
See the result in $SLEUTH_PATH/src/project/libtiff_project/CVE-ID/fix_save.txt, you can initially tell if the CVE is fully patched.