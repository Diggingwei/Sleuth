#!/bin/bash

VULN=$1
TOOL=$SLEUTH_PATH'/src/vuln_tool/evo_analysis.py'
TABLE=$SLEUTH_PATH'/src/vulnInfo/VulnTable.txt'
RENAME=$SLEUTH_PATH'/src/vuln_tool/evo_rename.py'
RENAME_2=$SLEUTH_PATH'/src/vuln_tool/rename.py'
TIMEOUT=10

if [[ -z $VULN ]];then
        echo "please input CVE!"
        exit 0
fi

if grep -q $VULN $TABLE; then
	PROJECT=$SLEUTH_PATH$(grep $VULN $TABLE | awk -F '\t' '{print $2}')
	INFO=$SLEUTH_PATH$(grep $VULN $TABLE | awk -F '\t' '{print $1}')
	EVO_INFO=$INFO'/evo_crash'
	OUTPUT=$EVO_INFO'/evo.txt'
	# TMPFILE=$INFO'/evo_save.txt'

	if [ -d $EVO_INFO'/seed_crash_final' ]; then
		echo 'reseting crash dir...'
		rm -rf $EVO_INFO'/seed_crash_final/'*
	else
		echo 'creating crash dir...'
		mkdir $EVO_INFO'/seed_crash_final'
	fi

	if [ -d $EVO_INFO'/seed_rename' ]; then
		echo 'reseting seed dir...'
		rm -rf $EVO_INFO'/seed_rename/'*
	else
		echo 'creating seed dir...'
		mkdir $EVO_INFO'/seed_rename'
	fi

	if [ -f $OUTPUT ]; then
		echo 'reseting crash file...'
		rm -rf $OUTPUT
	else
		echo 'creating crash file..'
		touch $OUTPUT
	fi

	TARGET=$EVO_INFO'/seed_crash_final/asan.txt'

	# EXE=$PROJECT'/'$(grep $VULN $TABLE | awk -F '\t' '{print $3}')
	
	FLAG=$(grep $VULN $TABLE | awk -F '\t' '{print $4}')
	INPUT=''
	INPUTDIR_1=$EVO_INFO'/seeds'

	if [ ! -d $INPUTDIR_1 ]; then
		echo "Not run Evocatio!"
		exit 1
	fi
	
	INPUTDIR_2=$PROJECT'/evo_fuzz_'$1
	INPUTDIR_3=$EVO_INFO'/seed_rename'
	TARGETDIR=$EVO_INFO'/seed_crash_final'
	OPT='halt_on_error=0'

	EXE=$(find $INPUTDIR_2 -type f -name '*_cov')

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

	LASTFILE=""
	NOWFILE=""

	python $RENAME $INPUTDIR_1 $INPUTDIR_3
	for file in `ls $INPUTDIR_3`
	do
		if [ -f $INPUTDIR_3'/'$file ]
		then
		 	INPUT=$INPUTDIR_3'/'$file
		 	PARAM="${FLAG/@@/$INPUT}"
		 	ASAN_OPTIONS=$TRACE_FORMAT:$LOG_PATH:$OPT bash -c "$EXE $PARAM" 2> "/dev/null" & pid=$!

		 	(sleep $TIMEOUT && kill -9 $pid 2>/dev/null) & watcher=$!

		 	if wait $pid 2>/dev/null; then
		 		kill -9 $watcher 2>/dev/null
		 	fi

		 	NOWFILE=$(ls -t $TARGETDIR | head -n1)
		 	if [ "$NOWFILE" != "LASTFILE" ]; then
		 		LASTFILE=$NOWFILE
		 		echo "$LASTFILE $INPUT" >> $OUTPUT
		 	fi
		fi
	done

	for dir in $(find $INPUTDIR_2 -type d -name 'out*'); do
		CRASH_SRC=$dir'/default/queue'
		python $RENAME_2 $CRASH_SRC
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

				NOWFILE=$(ls -t $TARGETDIR | head -n1)
				if [ "$NOWFILE" != "$LASTFILE" ]; then
					LASTFILE=$NOWFILE
					echo "$LASTFILE $INPUT" >> $OUTPUT
				fi
			fi
		done
	done

	# if [ -f $TMPFILE ]; then
		 #echo 'reseting file...'
		# rm -rf $TMPFILE
	# else
		# echo 'creating file..'
		# touch $TMPFILE
	# fi

	# python $TOOL $PROJECT $TARGETDIR $OUTPUT $INFO'/crash_example'> $TMPFILE

else
	echo 'no this CVE!'
fi

