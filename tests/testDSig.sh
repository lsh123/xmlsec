#!/bin/sh 

topfolder=$1
xmlsec_app=$2

timestamp=`date +%Y%m%d_%H%M%S` 
tmpfile=/tmp/testDSig.$timestamp-$$.tmp
logfile=/tmp/testDSig.$timestamp-$$.log
script="$0"
keysfile=$topfolder/keys.xml
valgrind_suppression="$topfolder/openssl.supp"
valgrind_options="--leak-check=yes --show-reachable=yes --num-callers=16 -v --suppressions=$valgrind_suppression"

if [ -n "$DEBUG_MEMORY" ] ; then 
    export VALGRIND="valgrind $valgrind_options"
    export REPEAT=3
    export EXTRA_PARAMS="--repeat $REPEAT"
fi

if [ -n "$PERF_TEST" ] ; then 
    export EXTRA_PARAMS="--repeat $PERF_TEST"
fi


printRes() {
    if [ $? = 0 ]; then
	echo "   OK"
    else 
        echo " Fail ($?)"
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
    echo "$xmlsec_app verify $2 $file.xml" >> $logfile
    $VALGRIND $xmlsec_app verify $EXTRA_PARAMS $2 $file.xml >> $logfile 2>> $logfile
    printRes 

    if [ -n "$3"  -a -z "$PERF_TEST" ] ; then
	printf "    Create new signature                                 "
	echo "$xmlsec_app sign $3 --output $tmpfile $file.tmpl" >> $logfile
	$VALGRIND $xmlsec_app sign --output $tmpfile $EXTRA_PARAMS $3 $file.tmpl >> $logfile 2>> $logfile
	printRes
	
	if [ -n "$4" ] ; then 
	    if [ -z "$VALGRIND" ] ; then 
		printf "    Verify new signature                                 "
		echo "$xmlsec_app verify $4 $tmpfile" >> $logfile
		$VALGRIND $xmlsec_app verify $EXTRA_PARAMS $4 $tmpfile >> $logfile 2>> $logfile
		printRes
	    fi
	fi
    fi
}

echo "--- testDSig started ($timestamp)" 
echo "--- log file is $logfile"
echo "--- testDSig started ($timestamp)" >> $logfile

execDSigTest "merlin-xmldsig-twenty-three/signature-enveloped-dsa" \
    " " \
    "--privkey $topfolder/keys/dsakey.pem" \
    " " 
    
execDSigTest "merlin-xmldsig-twenty-three/signature-enveloping-dsa" \
    " " \
    "--privkey $topfolder/keys/dsakey.pem" \
    " " 
    
execDSigTest "merlin-xmldsig-twenty-three/signature-enveloping-b64-dsa" \
    " " \
    "--privkey $topfolder/keys/dsakey.pem" \
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
    "--privkey $topfolder/keys/rsakey.pem" \
    " " 
    
execDSigTest "merlin-xmldsig-twenty-three/signature-external-b64-dsa" \
    " " \
    "--privkey $topfolder/keys/dsakey.pem" \
    " " 
    
execDSigTest "merlin-xmldsig-twenty-three/signature-external-dsa" \
    " " \
    "--privkey $topfolder/keys/dsakey.pem" \
    " " 

execDSigTest "merlin-xmldsig-twenty-three/signature-keyname" \
    "--pubkey:Lugh $topfolder/merlin-xmldsig-twenty-three/certs/lugh.key" \
    "--privkey:test-dsa $topfolder/keys/dsakey.pem" \
    "--privkey:test-dsa $topfolder/keys/dsakey.pem"

execDSigTest "merlin-xmldsig-twenty-three/signature-x509-crt" \
    "--trusted $topfolder/merlin-xmldsig-twenty-three/certs/ca.pem" \
    "--privkey $topfolder/keys/dsakey.pem,$topfolder/keys/dsacert.pem,$topfolder/keys/ca2cert.pem"\
    "--trusted $topfolder/keys/cacert.pem"

execDSigTest "merlin-xmldsig-twenty-three/signature-x509-sn" \
    "--trusted $topfolder/merlin-xmldsig-twenty-three/certs/ca.pem --untrusted $topfolder/merlin-xmldsig-twenty-three/certs/badb.pem" \
    "--privkey $topfolder/keys/dsakey.pem,$topfolder/keys/dsacert.pem,$topfolder/keys/ca2cert.pem"\
    "--trusted $topfolder/keys/cacert.pem"

execDSigTest "merlin-xmldsig-twenty-three/signature-x509-is" \
    "--trusted $topfolder/merlin-xmldsig-twenty-three/certs/ca.pem --untrusted $topfolder/merlin-xmldsig-twenty-three/certs/macha.pem" \
    "--privkey $topfolder/keys/dsakey.pem,$topfolder/keys/dsacert.pem,$topfolder/keys/ca2cert.pem"\
    "--trusted $topfolder/keys/cacert.pem"

execDSigTest "merlin-xmldsig-twenty-three/signature-x509-ski" \
    "--trusted $topfolder/merlin-xmldsig-twenty-three/certs/ca.pem --untrusted $topfolder/merlin-xmldsig-twenty-three/certs/nemain.pem" \
    "--privkey $topfolder/keys/dsakey.pem,$topfolder/keys/dsacert.pem,$topfolder/keys/ca2cert.pem"\
    "--trusted $topfolder/keys/cacert.pem"

execDSigTest "merlin-xmldsig-twenty-three/signature-retrievalmethod-rawx509crt" \
    "--trusted $topfolder/merlin-xmldsig-twenty-three/certs/ca.pem --untrusted $topfolder/merlin-xmldsig-twenty-three/certs/nemain.pem" \
    "--privkey $topfolder/keys/dsakey.pem"\
    "--trusted $topfolder/keys/cacert.pem --trusted $topfolder/keys/ca2cert.pem"
    
execDSigTest "merlin-xmldsig-twenty-three/signature" \
    "--trusted $topfolder/merlin-xmldsig-twenty-three/certs/merlin.pem" \
    "--privkey $topfolder/keys/dsakey.pem,$topfolder/keys/dsacert.pem,$topfolder/keys/ca2cert.pem" \
    "--trusted $topfolder/keys/cacert.pem --untrusted $topfolder/keys/ca2cert.pem"

execDSigTest "merlin-xmlenc-five/encsig-ripemd160-hmac-ripemd160-kw-tripledes" \
    "--keys $topfolder/merlin-xmlenc-five/keys.xml" \
    "--session-key hmac-192 --keys $topfolder/merlin-xmlenc-five/keys.xml" \
    "--keys $topfolder/merlin-xmlenc-five/keys.xml" 
    
execDSigTest "merlin-exc-c14n-one/exc-signature" \
    " " \
    "--privkey $topfolder/keys/dsakey.pem" \
    " " 
    
execDSigTest "aleksey-xmldsig-01/enveloping-dsa-x509chain" \
    "--trusted $topfolder/keys/cacert.pem --allowed-key-data x509" \
    "--privkey $topfolder/keys/dsakey.pem,$topfolder/keys/dsacert.pem,$topfolder/keys/ca2cert.pem" \
    "--trusted $topfolder/keys/cacert.pem --allowed-key-data x509"

execDSigTest "aleksey-xmldsig-01/enveloping-rsa-x509chain" \
    "--trusted $topfolder/keys/cacert.pem --allowed-key-data x509" \
    "--privkey $topfolder/keys/rsakey.pem,$topfolder/keys/rsacert.pem,$topfolder/keys/ca2cert.pem" \
    "--trusted $topfolder/keys/cacert.pem --allowed-key-data x509"

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
    "--trusted $topfolder/keys/cacert.pem --allowed-key-data x509 --verification-time 2002-10-02+10:00:00" 

execDSigTest "aleksey-xmldsig-01/dtd-hmac-91" \
    "--hmackey $topfolder/keys/hmackey.bin --dtdfile $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd" \
    "--hmackey $topfolder/keys/hmackey.bin --dtdfile $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd" \
    "--hmackey $topfolder/keys/hmackey.bin --dtdfile $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd"

execDSigTest "merlin-exc-c14n-one/exc-signature" \
    ""
    
execDSigTest "merlin-c14n-three/signature" \
    ""
    

execDSigTest "merlin-xpath-filter2-three/sign-xfdl" \
    ""

execDSigTest "merlin-xpath-filter2-three/sign-spec" \
    ""

echo "--------- Negative Testing: next test MUST FAIL ----------"
execDSigTest "merlin-xmldsig-twenty-three/signature-x509-crt-crl" \
    "--trusted $topfolder/merlin-xmldsig-twenty-three/certs/ca.pem"

execDSigTest "aleksey-xmldsig-01/enveloping-expired-cert" \
    "--trusted $topfolder/keys/cacert.pem --allowed-key-data x509" 

    
rm -rf $tmpfile
echo "--- testDSig finished" >> $logfile
echo "--- testDSig finished"
echo "--- detailed log is written to  $logfile" 



#merlin-xmldsig-twenty-three/signature-retrievalmethod-rawx509crt.xml
