#!/bin/sh

topfolder=$1
xmlsec_app=$2
file_format=$3
priv_format=$4

if [ "z$priv_format" = "zpkcs8" ]
then 
    priv_key_format="p8-$file_format"
else
    priv_key_format=$file_format
fi    
pub_key_format=$file_format
cert_format=$file_format


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
    --gen-key:test-hmac-sha1 hmac-192 \
    --gen-key:test-rsa rsa-1024  \
    --gen-key:test-dsa dsa-1024 \
    --gen-key:test-des des-192 \
    --gen-key:test-aes128 aes-128 \
    --gen-key:test-aes192 aes-192 \
    --gen-key:test-aes256 aes-256 \
    $keysfile >> $logfile 2>> $logfile
printRes 

rm -rf $tmpfile
echo "--- testKeys finished ---" >> $logfile
echo "--- testKeys finished ---"
echo "--- detailed log is written to  $logfile ---" 

