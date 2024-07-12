#/bin/bash

VULN=$1
TABLE=$SLEUTH_PATH'/src/vulnInfo/VulnTable.txt'
RENAME=$SLEUTH_PATH'/src/vuln_tool/rename.py'
TIMEOUT=10


if [[ -z $VULN ]];then
        echo "please input CVE!"
        exit 0
fi

if grep -q $VULN $TABLE; then
	PROJECT=$SLEUTH_PATH$(grep $VULN $TABLE | awk -F '\t' '{print $2}')
	INFO=$SLEUTH_PATH$(grep $VULN $TABLE | awk -F '\t' '{print $1}')
	AFL_INFO=$INFO'/afl_crash'
	SRC=$PROJECT'/comp_fuzz_'$1
	OUTPUT=$AFL_INFO'/comp.txt'
	
	if [ -d $AFL_INFO'/comp_crash_final' ]; then
		echo 'reseting crash dir...'
		rm -rf $AFL_INFO'/comp_crash_final/'*
	else
		echo 'creating crash dir...'
		mkdir $AFL_INFO'/comp_crash_final'
	fi

	if [ -f $OUTPUT ]; then
		echo 'reseting crash file...'
		rm -rf $OUTPUT
	else
		echo 'creating crash file..'
		touch $OUTPUT
        fi

	TRACE_FORMAT='stack_trace_format="[frame=%n, function=%f, location=%S]"'
	LOG_PATH='log_path='$AFL_INFO'/comp_crash_final/asan.txt'
	DIRWATCH=$AFL_INFO'/comp_crash_final'
	OPT='halt_on_error=0'

	EXE=$(find $SRC -type f -name '*_cov')
	FLAG=$(grep $VULN $TABLE | awk -F '\t' '{print $4}')
	INPUT=''

	# INITFILE=$(grep $VULN $TABLE | awk -F '\t' '{print $6}')

	#if [[ -z $INITFILE ]];then
        #        FILE=$INITFILE
        #else

	#	if [[ $INITFILE == '/tmp/foo' ]] || [[ $INITFILE == '/dev/null' ]]; then
        #        	FILE=$INITFILE
        #	else
        #        	FILE=$INFO'/'$INITFILE
        #	fi
	#fi

	LASTFILE=''
	NOWFILE=''

	for dir in $(find $SRC -type d -name 'out*'); do
		CRASH_SRC=$dir'/default/crashes'
		python $RENAME $CRASH_SRC
		for file in `ls $CRASH_SRC`
		do
			if [ -f $CRASH_SRC"/"$file ]
			then
				INPUT=$CRASH_SRC"/"$file
				PARAM="${FLAG/@@/$INPUT}"
				ASAN_OPTIONS=$TRACE_FORMAT:$LOG_PATH:$OPT bash -c "$EXE $PARAM" 2> "/dev/null" & pid=$!

				(sleep $TIMEOUT && kill -9 $pid 2>/dev/null) & watcher=$!

				if wait $pid 2>/dev/null; then
					kill -9 $watcher 2>/dev/null
				fi

				NOWFILE=$(ls -t $DIRWATCH | head -n1)
				if [ "$NOWFILE" != "$LASTFILE" ]; then
					LASTFILE=$NOWFILE
					echo "$LASTFILE $INPUT" >> $OUTPUT
				fi
			fi
		done
	done
else
	echo 'no this CVE!'
fi

