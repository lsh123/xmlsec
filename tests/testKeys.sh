#!/bin/sh 

topfolder=$1
xmlsec_app=$2

timestamp=`date +%Y%m%d_%H%M%S` 
tmpfile=/tmp/testKeys.$timestamp-$$.tmp
logfile=/tmp/testKeys.$timestamp-$$.log
script="$0"
keysfile=$topfolder/keys.xml

#
# It's just too slow
#
#valgrind_suppressions="$topfolder/openssl.supp"
#valgrind_options="--error-limit=no --leak-check=yes --show-reachable=yes --num-callers=16 -v --suppressions=$valgrind_suppressions"
#if [ -n "$DEBUG_MEMORY" ] ; then 
#    export VALGRIND="valgrind $valgrind_options"
#    export REPEAT=1
#    export EXTRA_PARAMS="--repeat $REPEAT"
#fi

printRes() {
    if [ $? = 0 ]; then
	echo "   OK"
    else 
        echo " Fail"
    fi
    if [ -f .memdump ] ; then 
	cat .memdump >> $logfile 
    fi
}

echo "--- testKeys started ($timestamp) ---"
echo "--- testKeys started ($timestamp) ---" >> $logfile

printf "    Creating new keys                                    "
$VALGRIND $xmlsec_app keys \
    --gen-hmac "test-hmac-sha1" \
    --gen-rsa "test-rsa" \
    --gen-dsa "test-dsa" \
    --gen-des3 "test-des" \
    --gen-aes128 "test-aes128" \
    --gen-aes192 "test-aes192" \
    --gen-aes256 "test-aes256" \
    $keysfile >> $logfile 2>> $logfile
printRes 

rm -rf $tmpfile
echo "--- testKeys finished ---" >> $logfile
echo "--- testKeys finished ---"
echo "--- detailed log is written to  $logfile ---" 

