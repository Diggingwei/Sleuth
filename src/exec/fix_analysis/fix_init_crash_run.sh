#/bin/bash

VULN=$1
TABLE=$SLEUTH_PATH'/src/vulnInfo/VulnTable.txt'
TIMEOUT=10

if [[ -z $VULN ]];then
	echo "please input CVE!"
	exit 0
fi

if grep -q $VULN $TABLE; then
	PROJECT=$SLEUTH_PATH$(grep $VULN $TABLE | awk -F '\t' '{print $2}')
	# INFO=$PROJECT'/../'$VULN
	INFO=$SLEUTH_PATH$(grep $VULN $TABLE | awk -F '\t' '{print $1}')
	SLEUTH_INFO=$INFO'/sleuth_crash'
	SRC=$PROJECT'/fix_fuzz_'$1
	SEEDSRC=$PROJECT'/fuzz_'$1
	OUTPUT=$SLEUTH_INFO'/fix_init.txt'
	
	if [ -d $SLEUTH_INFO'/fix_crash_final' ]; then
		echo 'reseting crash dir...'
		rm -rf $SLEUTH_INFO'/fix_crash_final/'*
	else
		echo 'creating crash dir...'
		mkdir $SLEUTH_INFO'/fix_crash_final'
	fi

	if [ -f $OUTPUT ]; then
		echo 'reseting crash file...'
		rm -rf $OUTPUT
	else
		echo 'creating crash file..'
		touch $OUTPUT
	fi

	TRACE_FORMAT='stack_trace_format="[frame=%n, function=%f, location=%S]"'
	LOG_PATH='log_path='$SLEUTH_INFO'/fix_crash_final/asan.txt'
	DIRWATCH=$SLEUTH_INFO'/fix_crash_final'
	OPT='halt_on_error=0'

	EXE=$(find $SRC -type f -name '*_cov')
	#EXE=$PROJECT'/'$(grep $VULN $TABLE | awk -F '\t' '{print $3}')
	FLAG=$(grep $VULN $TABLE | awk -F '\t' '{print $4}')
	INPUT=''
	
	#INITFILE=$(grep $VULN $TABLE | awk -F '\t' '{print $6}')

	#if [[ -z $INITFILE ]];then
	#	FILE=$INITFILE
	#else
	#	if [[ $INITFILE == '/tmp/foo' ]] || [[ $INITFILE == '/dev/null' ]]; then
	#		FILE=$INITFILE
	#	else
	#		FILE=$INFO'/'$INITFILE
	#	fi
	#fi

	LASTFILE=''
	NOWFILE=''

	for dir in $(find $SEEDSRC -type d -name 'out*'); do
		CRASH_SRC=$dir'/default/crashes'
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

