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
tmpfile=$TMPFOLDER/testXKMS.$timestamp-$$.tmp
tmpfile2=$TMPFOLDER/testXKMS.$timestamp-$$-2.tmp
tmpfile3=$TMPFOLDER/testXKMS.$timestamp-$$-3.tmp
logfile=$TMPFOLDER/testXKMS.$timestamp-$$.log
script="$0"

# prepate crypto config folder
crypto_config=$TMPFOLDER/xmlsec-crypto-config
keysfile=$crypto_config/keys.xml

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
    xmlsec_params="$xmlsec_params --repeat $PERF_TEST"
fi

# debug 
# xmlsec_params="$xmlsec_params --xkms-stop-on-unknown-response-mechanism --xkms-stop-on-unknown-respond-with --xkms-stop-on-unknown-key-usage"
        

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

execXkmsServerRequestTest() {    
    src_file=$topfolder/$1.xml
    res_file=$topfolder/$1-$2.xml
    echo "$1 ($2)"

    rm -f $tmpfile $tmpfile2 $tmpfile3
    
    printf "    Processing xkms request                              "
    echo "$xmlsec_app --xkms-server-request --output $tmpfile $xmlsec_params $3 $src_file" >> $logfile
    $VALGRIND $xmlsec_app --xkms-server-request  --output $tmpfile $xmlsec_params $3 $src_file >> $logfile 2>> $logfile
    if [ $? = 0 ]; then
	# cleanup Id attribute because it is generated every time
	sed 's/ Id="[^\"]*"/ Id=""/g' $res_file > $tmpfile2
	sed 's/ Id="[^\"]*"/ Id=""/g' $tmpfile > $tmpfile3
	diff $tmpfile2 $tmpfile3 >> $logfile 2>> $logfile
	printRes $?
    else 
	echo " Error"
    fi
}

echo "--- testXKMS started for xmlsec-$crypto library ($timestamp)" 
echo "--- LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
echo "--- log file is $logfile"
echo "--- testXKMS started for xmlsec-$crypto library ($timestamp)" >> $logfile
echo "--- LD_LIBRARY_PATH=$LD_LIBRARY_PATH" >> $logfile

execXkmsServerRequestTest \
    "aleksey-xkms-01/locate-example-1" "no-match" \
    "--xkms-service http://www.example.com/xkms"

execXkmsServerRequestTest \
    "aleksey-xkms-01/locate-example-1" "bad-service" \
    "--xkms-service http://www.example.com/xkms-bad-service"

execXkmsServerRequestTest \
    "aleksey-xkms-01/locate-example-2" "no-match" \
    "--xkms-service http://www.example.com/xkms"

execXkmsServerRequestTest \
    "aleksey-xkms-01/validate-example-1" "no-match" \
    "--xkms-service http://www.example.com/xkms"

execXkmsServerRequestTest \
    "aleksey-xkms-01/locate-opaque-client-data" "no-match" \
    "--xkms-service http://www.example.com/xkms"

execXkmsServerRequestTest \
    "aleksey-xkms-01/compound-example-1" "no-match" \
    "--xkms-service http://www.example.com/xkms"

execXkmsServerRequestTest \
    "aleksey-xkms-01/status-request" "success" \
    "--xkms-service http://www.example.com/xkms"

execXkmsServerRequestTest \
    "aleksey-xkms-01/bad-request-name" "not-supported" \
    "--xkms-service http://www.example.com/xkms"

execXkmsServerRequestTest \
    "aleksey-xkms-01/soap12-locate-example-1" "no-match" \
    "--xkms-service http://www.example.com/xkms --xkms-format soap-1.2"

execXkmsServerRequestTest \
    "aleksey-xkms-01/soap11-locate-example-1" "unsupported" \
    "--xkms-service http://www.example.com/xkms --xkms-format soap-1.2"

execXkmsServerRequestTest \
    "aleksey-xkms-01/soap12-bad-request-name" "msg-invalid" \
    "--xkms-service http://www.example.com/xkms --xkms-format soap-1.2"

execXkmsServerRequestTest \
    "aleksey-xkms-01/soap11-locate-example-1" "no-match" \
    "--xkms-service http://www.example.com/xkms --xkms-format soap-1.1"

execXkmsServerRequestTest \
    "aleksey-xkms-01/soap12-locate-example-1" "unsupported" \
    "--xkms-service http://www.example.com/xkms --xkms-format soap-1.1"

execXkmsServerRequestTest \
    "aleksey-xkms-01/soap11-bad-request-name" "msg-invalid" \
    "--xkms-service http://www.example.com/xkms --xkms-format soap-1.1"


rm -f $tmpfile $tmpfile2 $tmpfile3

echo "--- testXKMS finished" >> $logfile
echo "--- testXKMS finished"
echo "--- detailed log is written to  $logfile" 

