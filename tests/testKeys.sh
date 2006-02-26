#!/bin/sh

crypto=$1
topfolder=$2
xmlsec_app=$3
file_format=$4

pub_key_format=$file_format
cert_format=$file_format
priv_key_option="--pkcs12"
priv_key_format="p12"

if [ "z$TMPFOLDER" = "z" ] ; then
    TMPFOLDER=/tmp
fi

timestamp=`date +%Y%m%d_%H%M%S` 
tmpfile=$TMPFOLDER/testKeys.$timestamp-$$.tmp
logfile=$TMPFOLDER/testKeys.$timestamp-$$.log
script="$0"
nssdbfolder=$topfolder/nssdb

# prepate crypto config folder
crypto_config=$TMPFOLDER/xmlsec-crypto-config
keysfile=$crypto_config/keys.xml
mkdir -p $crypto_config
rm -rf $crypto_config/*

valgrind_suppression="--suppressions=$topfolder/openssl.supp --suppressions=$topfolder/nss.supp"
valgrind_options="--leak-check=yes --show-reachable=yes --num-callers=32 -v"


if [ "z$crypto" != "z" -a "z$crypto" != "zdefault" ] ; then
    xmlsec_params="$xmlsec_params --crypto $crypto"
fi
xmlsec_params="$xmlsec_params --crypto-config $crypto_config"

if [ -n "$DEBUG_MEMORY" ] ; then 
    export VALGRIND="valgrind $valgrind_options"
    export REPEAT=3
    xmlsec_params="$xmlsec_params --repeat $REPEAT"
fi

if [ -n "$PERF_TEST" ] ; then 
    export xmlsec_params="$xmlsec_params --repeat $PERF_TEST"
fi

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

execKeysTest() {    
    req_key_data=$1
    key_name=$2
    alg_name=$3

    if [ -n "$req_key_data" ] ; then
	printf "    Checking $req_key_data key data presense                      "
        echo "$xmlsec_app check-key-data $req_key_data" >> $logfile
	$xmlsec_app check-key-data $req_key_data >> $logfile 2>> $logfile
	res=$?
	if [ $res = 0 ]; then
    	    echo "   OK"	    
	else
	    echo " Skip"
	    return
	fi
    fi

    printf "    Creating new key: $alg_name                           "

    params="--gen-key:$key_name $alg_name"
    if [ -f $keysfile ] ; then
	params="$params --keys-file $keysfile"	
    fi

    echo "$xmlsec_app keys $params $xmlsec_params $keysfile" >>  $logfile 
    $VALGRIND $xmlsec_app keys $params $xmlsec_params $keysfile >> $logfile 2>> $logfile
    printRes $?
}

echo "--- testKeys started for xmlsec-$crypto library ($timestamp) ---"
echo "--- LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
echo "--- log file is $logfile"
echo "--- testKeys started for xmlsec-$crypto library ($timestamp) ---" >> $logfile
echo "--- LD_LIBRARY_PATH=$LD_LIBRARY_PATH" >> $logfile

# remove old keys file and copy NSS DB files if needed
rm -rf $keysfile
if [ "z$crypto" = "znss" ] ; then
    cp -f $nssdbfolder/*.db $crypto_config
fi

execKeysTest \
	"hmac" \
	"test-hmac-sha1" \
	"hmac-192"
execKeysTest \
	"rsa " \
	"test-rsa      " \
	"rsa-1024"
execKeysTest \
	"dsa " \
	"test-dsa      " \
	"dsa-1024"
execKeysTest \
	"des " \
	"test-des      " \
    	"des-192 "
execKeysTest \
	"aes " \
	"test-aes128   " \
	"aes-128 "
execKeysTest \
	"aes " \
	"test-aes192   " \
	"aes-192 "
execKeysTest \
	"aes " \
	"test-aes256   " \
	"aes-256 "

echo "--- testKeys finished ---" >> $logfile
echo "--- testKeys finished ---"
echo "--- detailed log is written to  $logfile ---" 

