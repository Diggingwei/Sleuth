#!/bin/bash

VULN=$1
VULNFILE=$2
TOOL='get_trace.py'
TABLE=$SLEUTH_PATH'/src/vulnInfo/VulnTable.txt'


if [[ -z $VULN ]];then
        echo "please input CVE!"
        exit 0
fi

if grep -q $VULN $TABLE; then
	PROJECT=$SLEUTH_PATH$(grep $VULN $TABLE | awk -F '\t' '{print $2}')
	INFO=$SLEUTH_PATH$(grep $VULN $TABLE | awk -F '\t' '{print $1}')

	if [ -d $INFO'/crash_example' ]; then
		echo 'reseting...'
		rm -rf $INFO'/crash_example/'*
	else
		echo 'creating...'
		mkdir $INFO'/crash_example'
	fi

	echo '==============================='

	TARGET=$INFO'/crash_example/asan.txt'

	EXE=$PROJECT'/'$(grep $VULN $TABLE | awk -F '\t' '{print $3}')
	FLAG=$(grep $VULN $TABLE | awk -F '\t' '{print $4}')
	# INPUT=$INFO'/'$(grep $VULN $TABLE | awk -F '\t' '{print $5}')

	# INITFILE=$(grep $VULN $TABLE | awk -F '\t' '{print $6}')

	#if [[ -z $INITFILE ]];then
	#	FILE=$INITFILE
	#else

	#	if [[ $INITFILE == '/tmp/foo' ]] || [[ $INITFILE == '/dev/null' ]]; then
	#		FILE=$INITFILE
	#	else
	#		FILE=$INFO'/'$INITFILE
	#	fi
	#fi

	TRACE_FORMAT='stack_trace_format="[frame=%n, function=%f, location=%S]"'
	LOG_PATH='log_path='$TARGET
	OPT='halt_on_error=0'

	INPUT=$INFO'/poc'

	PARAM="${FLAG/@@/$INPUT}"

	echo $EXE $PARAM

	ASAN_OPTIONS=$TRACE_FORMAT:$LOG_PATH:$OPT $EXE $PARAM
	echo '==============================='

	if ls $TARGET*; then
        	python $TOOL `ls $TARGET*` $VULNFILE
	else
        	echo 'no TARGET!'
	fi
else
	echo 'no this CVE!'
fi

