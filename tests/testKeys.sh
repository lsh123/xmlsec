#!/bin/sh

binfolder=../apps
topfolder=.
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
$binfolder/xmlsec keys \
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

