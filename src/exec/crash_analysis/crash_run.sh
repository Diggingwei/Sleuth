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

if [ -d $INFO'/sleuth_crash' ]; then
	echo 'reseting...'
	rm -rf $INFO'/sleuth_crash/'*
else
	echo 'creating sleuth_crash dir...'
	mkdir $INFO'/sleuth_crash'
fi

if [ -d $INFO'/afl_crash' ]; then
	echo 'reseting...'
	rm -rf $INFO'/afl_crash/'*
else
	echo 'creating afl_crash dir...'
	mkdir $INFO'/afl_crash'
fi

if grep -q $VULN $TABLE; then

	echo '=========================='
	echo 'Analyzing Sleuth crash......'
	./init_crash_run.sh $VULN
	echo '=========================='
	echo 'Analyzing AFL crash......'
	./comp_crash_run.sh $VULN
	echo '=========================='
	echo 'Analyzing Evocatio crash......'
	./crash_evo.sh $VULN
	echo '========================='

	# python analysis.py $INFO'/crash_final' $INFO'/comp_crash_final' $INFO'/init.txt' $INFO'/comp.txt' > $INFO'/save.txt'
	python $ANALYSIS $PROJECT $INFO'/sleuth_crash/crash_final' $INFO'/sleuth_crash/init.txt' $INFO'/afl_crash/comp_crash_final' $INFO'/afl_crash/comp.txt' $INFO'/evo_crash/seed_crash_final' $INFO'/evo_crash/evo.txt' $INFO'/crash_example' > $INFO'/save.txt'
else
	echo 'no this CVE!'
fi
