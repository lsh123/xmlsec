#!/bin/sh

topfolder=$1
xmlsec_app=$2

timestamp=`date +%Y%m%d_%H%M%S` 
tmpfile=/tmp/testKeys.$timestamp-$$.tmp
logfile=/tmp/testKeys.$timestamp-$$.log
script="$0"
keysfile=$topfolder/keys.xml

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
$xmlsec_app keys \
    --gen-hmac-192  "test-hmac-sha1" \
    --gen-rsa-1024  "test-rsa" \
    --gen-dsa-1024  "test-dsa" \
    --gen-des-192   "test-des" \
    --gen-aes-128   "test-aes128" \
    --gen-aes-192   "test-aes192" \
    --gen-aes-256   "test-aes256" \
    $keysfile >> $logfile 2>> $logfile
printRes 

rm -rf $tmpfile
echo "--- testKeys finished ---" >> $logfile
echo "--- testKeys finished ---"
echo "--- detailed log is written to  $logfile ---" 

