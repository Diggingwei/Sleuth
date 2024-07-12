#!/bin/bash

VULN=$1
TABLE=$SLEUTH_PATH'/src/vulnInfo/VulnTable.txt'
TMINTOOL=$SLEUTH_PATH'/Evocatio/bug-severity-AFLplusplus/afl-tmin-lazy'
INFERTOOL=$SLEUTH_PATH'/Evocatio/bug-severity-AFLplusplus/cd-bytes-identifier'

if [[ -z $VULN ]];then
        echo "please input CVE!"
        exit 0
fi

if grep -q $VULN $TABLE; then
	PROJECT=$SLEUTH_PATH$(grep $VULN $TABLE | awk -F '\t' '{print $2}')
	INFO=$SLEUTH_PATH$(grep $VULN $TABLE | awk -F '\t' '{print $1}')
	EVO_INFO=$INFO'/evo_crash'

	if [ -d $EVO_INFO ]; then
		echo 'reseting...'
		rm -rf $EVO_INFO'/'*
		mkdir $EVO_INFO'/seeds'
	else
		echo 'creating...'
		mkdir -p $EVO_INFO'/seeds'
	fi

	echo '==============================='

	EXE=$PROJECT'/'$(grep $VULN $TABLE | awk -F '\t' '{print $3}')
	FLAG=$(grep $VULN $TABLE | awk -F '\t' '{print $4}')
	INPUT=$INFO'/poc'
	# INPUT=$INFO'/'$(grep $VULN $TABLE | awk -F '\t' '{print $5}')
    	OUTPUT=$EVO_INFO'/poc_1'
    	SEEDSFILE=$EVO_INFO'/seeds'

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

    $TMINTOOL -m none -i $INPUT -o $OUTPUT -- $EXE $FLAG

    if [[ -f $OUTPUT ]];then
        $INFERTOOL -m none -i $OUTPUT -o /tmp/foo -g -c /tmp/constraints.res -k $SEEDSFILE -- $EXE $FLAG
    else
        echo 'Tmin Failed'
    fi

	echo '==============================='

else
	echo 'no this CVE!'
fi
