#!/bin/bash

VULN=$1
TABLE=$SLEUTH_PATH'/src/vulnInfo/VulnTable.txt'
ANALYSIS=$SLEUTH_PATH'/src/vuln_tool/asan_analysis.py'
INFO=$SLEUTH_PATH$(grep $VULN $TABLE | awk -F '\t' '{print $1}')
PROJECT=$SLEUTH_PATH$(grep $VULN $TABLE | awk -F '\t' '{print $2}')

if [[ -z $VULN ]];then
        echo "please input CVE!"
        exit 0
fi

if grep -q $VULN $TABLE; then

	echo '=========================='
	echo 'Analyzing Sleuth crash......'
	./fix_init_crash_run.sh $VULN
	echo '=========================='
	echo 'Analyzing AFL crash......'
	./fix_comp_crash_run.sh $VULN
	echo '========================='
	echo 'Analyzing Evocatio crash......'
	./fix_evo_crash_run.sh $VULN
	echo '========================='

	# python analysis.py $INFO'/crash_final' $INFO'/comp_crash_final' $INFO'/init.txt' $INFO'/comp.txt' > $INFO'/save.txt'
	python $ANALYSIS $PROJECT $INFO'/sleuth_crash/fix_crash_final' $INFO'/sleuth_crash/fix_init.txt' $INFO'/afl_crash/fix_comp_crash_final' $INFO'/afl_crash/fix_comp.txt' $INFO'/evo_crash/fix_evo_crash_final' $INFO'/evo_crash/fix_evo.txt' $INFO'/crash_example' > $INFO'/fix_save.txt'
else
	echo 'no this CVE!'
fi
