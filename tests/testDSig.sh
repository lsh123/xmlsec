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
tmpfile=/tmp/testDSig.$timestamp-$$.tmp
logfile=/tmp/testDSig.$timestamp-$$.log
script="$0"
keysfile=$topfolder/keys.xml
valgrind_suppression="--suppressions=$topfolder/openssl.supp --suppressions=$topfolder/nss.supp"
valgrind_options="--leak-check=yes --show-reachable=yes --num-callers=32 -v"

if [ -n "$DEBUG_MEMORY" ] ; then 
    export VALGRIND="valgrind $valgrind_options"
    export REPEAT=3
    export EXTRA_PARAMS="--repeat $REPEAT"
fi

if [ -n "$PERF_TEST" ] ; then 
    export EXTRA_PARAMS="--repeat $PERF_TEST"
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

execDSigTest() {    
    file=$topfolder/$1      
    echo $1

    rm -f $tmpfile
        
    printf "    Verify existing signature                            "
    echo "$xmlsec_app verify --crypto-config $crypto_config $2 $file.xml" >> $logfile
    $VALGRIND $xmlsec_app verify --crypto-config $crypto_config $EXTRA_PARAMS $2 $file.xml >> $logfile 2>> $logfile
    printRes $?

    if [ -n "$3"  -a -z "$PERF_TEST" ] ; then
	printf "    Create new signature                                 "
	echo "$xmlsec_app sign --crypto-config $crypto_config $3 --output $tmpfile $file.tmpl" >> $logfile
	$VALGRIND $xmlsec_app sign --crypto-config $crypto_config --output $tmpfile $EXTRA_PARAMS $3 $file.tmpl >> $logfile 2>> $logfile
	printRes $?
	
	if [ -n "$4" ] ; then 
	    if [ -z "$VALGRIND" ] ; then 
		printf "    Verify new signature                                 "
		echo "$xmlsec_app verify --crypto-config $crypto_config $4 $tmpfile" >> $logfile
		$VALGRIND $xmlsec_app verify --crypto-config $crypto_config $EXTRA_PARAMS $4 $tmpfile >> $logfile 2>> $logfile
		printRes $?
	    fi
	fi
    fi
}

echo "--- testDSig started ($timestamp)" 
echo "--- log file is $logfile"
echo "--- testDSig started ($timestamp)" >> $logfile

execDSigTest "merlin-xmldsig-twenty-three/signature-enveloped-dsa" \
    " " \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret" \
    " " 
    
execDSigTest "merlin-xmldsig-twenty-three/signature-enveloping-dsa" \
    " " \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret" \
    " " 
    
execDSigTest "merlin-xmldsig-twenty-three/signature-enveloping-b64-dsa" \
    " " \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret" \
    " " 
    
execDSigTest "merlin-xmldsig-twenty-three/signature-enveloping-hmac-sha1-40" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 
    
execDSigTest "merlin-xmldsig-twenty-three/signature-enveloping-hmac-sha1" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "merlin-xmldsig-twenty-three/signature-enveloping-rsa" \
    " " \
    "$priv_key_option $topfolder/keys/rsakey.$priv_key_format --pwd secret" \
    " " 
    
execDSigTest "merlin-xmldsig-twenty-three/signature-external-b64-dsa" \
    " " \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret" \
    " " 
    
execDSigTest "merlin-xmldsig-twenty-three/signature-external-dsa" \
    " " \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret" \
    " " 

execDSigTest "merlin-xmldsig-twenty-three/signature-keyname" \
    "--pubkey-$pub_key_format:Lugh $topfolder/merlin-xmldsig-twenty-three/certs/lugh.$pub_key_format" \
    "$priv_key_option:test-dsa $topfolder/keys/dsakey.$priv_key_format --pwd secret" \
    "$priv_key_option:test-dsa $topfolder/keys/dsakey.$priv_key_format --pwd secret"

execDSigTest "merlin-xmldsig-twenty-three/signature-x509-crt" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format"

execDSigTest "merlin-xmldsig-twenty-three/signature-x509-sn" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format --untrusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/badb.$cert_format" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format"

execDSigTest "merlin-xmldsig-twenty-three/signature-x509-is" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format --untrusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/macha.$cert_format" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format"

execDSigTest "merlin-xmldsig-twenty-three/signature-x509-ski" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format --untrusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/nemain.$cert_format" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format"

execDSigTest "merlin-xmldsig-twenty-three/signature-retrievalmethod-rawx509crt" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format --untrusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/nemain.$cert_format" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --trusted-$cert_format $topfolder/keys/ca2cert.$cert_format"
    
execDSigTest "merlin-xmldsig-twenty-three/signature" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/merlin.$cert_format" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format"

execDSigTest "merlin-xmlenc-five/encsig-ripemd160-hmac-ripemd160-kw-tripledes" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" \
    "--session-key hmac-192 --keys-file $topfolder/merlin-xmlenc-five/keys.xml" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" 
    
execDSigTest "merlin-exc-c14n-one/exc-signature" \
    " " \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret" \
    " " 
    
execDSigTest "aleksey-xmldsig-01/enveloping-dsa-x509chain" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest "aleksey-xmldsig-01/enveloping-rsa-x509chain" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/rsakey.$priv_key_format --pwd secret" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest "aleksey-xmldsig-01/enveloping-hmac-ripemd160" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "aleksey-xmldsig-01/enveloping-hmac-ripemd160-64" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "aleksey-xmldsig-01/enveloping-hmac-md5" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "aleksey-xmldsig-01/enveloping-hmac-md5-64" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "aleksey-xmldsig-01/xpointer-hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "aleksey-xmldsig-01/enveloping-expired-cert" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509 --verification-time 2002-04-17+10:00:00" 

execDSigTest "aleksey-xmldsig-01/dtd-hmac-91" \
    "--hmackey $topfolder/keys/hmackey.bin --dtd-file $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd" \
    "--hmackey $topfolder/keys/hmackey.bin --dtd-file $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd" \
    "--hmackey $topfolder/keys/hmackey.bin --dtd-file $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd"

execDSigTest "aleksey-xmldsig-01/x509data-test" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format" \
    "$priv_key_option tests/keys/rsakey.$priv_key_format --pwd secret" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format"

execDSigTest "merlin-exc-c14n-one/exc-signature" \
    ""
    
execDSigTest "merlin-c14n-three/signature" \
    ""
    
execDSigTest "merlin-xpath-filter2-three/sign-xfdl" \
    ""

execDSigTest "merlin-xpath-filter2-three/sign-spec" \
    ""

# test dynamic signature
echo "Dynamic signature template"
printf "    Create new signature                                 "
echo "$xmlsec_app sign-tmpl --crypto-config $crypto_config --keys-file $topfolder/keys.xml --output $tmpfile" >> $logfile
$VALGRIND $xmlsec_app sign-tmpl --crypto-config $crypto_config $EXTRA_PARAMS --keys-file $topfolder/keys.xml --output $tmpfile >> $logfile 2>> $logfile
printRes $?
printf "    Verify new signature                                 "
echo "$xmlsec_app verify --crypto-config $crypto_config --keys-file $topfolder/keys.xml $tmpfile" >> $logfile
$VALGRIND $xmlsec_app verify --crypto-config $crypto_config $EXTRA_PARAMS --keys-file $topfolder/keys.xml $tmpfile >> $logfile 2>> $logfile
printRes $?



echo "--------- Negative Testing: next test MUST FAIL ----------"
execDSigTest "merlin-xmldsig-twenty-three/signature-x509-crt-crl" \
    "--X509-skip-strict-checks --trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format"

execDSigTest "aleksey-xmldsig-01/enveloping-expired-cert" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" 

execDSigTest "aleksey-xmldsig-01/dtd-hmac-91" \
    "--enabled-reference-uris empty --hmackey $topfolder/keys/hmackey.bin --dtd-file $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd" 

rm -rf $tmpfile

echo "--- testDSig finished" >> $logfile
echo "--- testDSig finished"
echo "--- detailed log is written to  $logfile" 

