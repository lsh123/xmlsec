#!/bin/sh

topfolder=$1
xmlsec_app=$2
file_format=$3

pub_key_format=$file_format
cert_format=$file_format
crypto_config=$topfolder
priv_key_option="--pkcs12"
priv_key_format="p12"

timestamp=`date +%Y%m%d_%H%M%S` 
tmpfile=/tmp/testKeys.$timestamp-$$.tmp
logfile=/tmp/testKeys.$timestamp-$$.log
script="$0"
keysfile=$topfolder/keys.xml

printRes() {	
    if [ $1 = 0 ]; then
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
$xmlsec_app keys --crypto-config $crypto_config \
    --gen-key:test-hmac-sha1 hmac-192 \
    --gen-key:test-rsa rsa-1024  \
    --gen-key:test-dsa dsa-1024 \
    --gen-key:test-des des-192 \
    --gen-key:test-aes128 aes-128 \
    --gen-key:test-aes192 aes-192 \
    --gen-key:test-aes256 aes-256 \
    $keysfile >> $logfile 2>> $logfile
printRes $?

rm -rf $tmpfile

echo "--- testKeys finished ---" >> $logfile
echo "--- testKeys finished ---"
echo "--- detailed log is written to  $logfile ---" 

