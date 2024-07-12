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
	EVO_INFO=$INFO'/evo_crash'
	SRC=$PROJECT'/fix_fuzz_'$1
	SEEDSRC=$PROJECT'/evo_fuzz_'$1
	SEEDSRC_2=$EVO_INFO'/seed_rename'
	OUTPUT=$EVO_INFO'/fix_evo.txt'
	
	if [ -d $EVO_INFO'/fix_evo_crash_final' ]; then
		echo 'reseting...'
		rm -rf $EVO_INFO'/fix_evo_crash_final/'*
	else
		echo 'creating...'
		mkdir $EVO_INFO'/fix_evo_crash_final'
	fi

	if [ -f $OUTPUT ]; then
		echo 'reseting file...'
		rm -rf $OUTPUT
	else
		echo 'creating file..'
		touch $OUTPUT
        fi

	TRACE_FORMAT='stack_trace_format="[frame=%n, function=%f, location=%S]"'
	LOG_PATH='log_path='$EVO_INFO'/fix_evo_crash_final/asan.txt'
	DIRWATCH=$EVO_INFO'/fix_evo_crash_final'
	OPT='halt_on_error=0'

	EXE=$(find $SRC -type f -name '*_cov')
	# EXE=$PROJECT'/'$(grep $VULN $TABLE | awk -F '\t' '{print $3}')
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

	for file in `ls $SEEDSRC_2`
	do
		if [ -f $SEEDSRC_2'/'$file ]
		then
			INPUT=$SEEDSRC_2'/'$file
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

	for dir in $(find $SEEDSRC -type d -name 'out*'); do
		CRASH_SRC=$dir'/default/queue'
		for file in `ls $CRASH_SRC/poc* 2>/dev/null` 
		do
			if [ -f $file ]
			then
				INPUT=$file
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

