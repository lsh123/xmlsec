#!/bin/sh 

topfolder=.
binfolder=../apps
timestamp=`date +%Y%m%d_%H%M%S` 
tmpfile=/tmp/testDSig.$timestamp-$$.tmp
logfile=/tmp/testDSig.$timestamp-$$.log
script="$0"
keysfile=$topfolder/keys.xml

if [ -n "$DEBUG_MEMORY" ] ; then 
    export VALGRIND="valgrind --leak-check=yes --show-reachable=yes --num-callers=16"
    export RETRY=10
    export EXTRA_PARAMS="--retry $retry"
fi

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

execDSigTest() {    
    file=$topfolder/$1      
    echo $1
    
    printf "    Verify existing signature                            "
    echo "$binfolder/xmlsec verify $2 $file.xml" >> $logfile
    $VALGRIND $binfolder/xmlsec verify $2 $file.xml >> $logfile 2>> $logfile
    printRes 

    if [ -n "$3" ] ; then
	printf "    Create new signature                                 "
	echo "$binfolder/xmlsec sign $3 $file.tmpl" >> $logfile
	$VALGRIND $binfolder/xmlsec sign $3 $file.tmpl > $tmpfile 2>> $logfile
	printRes
	
	if [ -n "$4" ] ; then 
	    if [ -z "$VALGRIND" ] ; then 
		printf "    Verify new signature                                 "
		echo "$binfolder/xmlsec verify $4 $tmpfile" >> $logfile
		$VALGRIND $binfolder/xmlsec verify $4 $tmpfile >> $logfile 2>> $logfile
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
    "--privkey keys/dsakey.pem" \
    " " 
    
execDSigTest "merlin-xmldsig-twenty-three/signature-enveloping-dsa" \
    " " \
    "--privkey keys/dsakey.pem" \
    " " 
    
execDSigTest "merlin-xmldsig-twenty-three/signature-enveloping-b64-dsa" \
    " " \
    "--privkey keys/dsakey.pem" \
    " " 
    
execDSigTest "merlin-xmldsig-twenty-three/signature-enveloping-hmac-sha1-40" \
    "--hmackey keys/hmackey.bin" \
    "--hmackey keys/hmackey.bin" \
    "--hmackey keys/hmackey.bin" 
    
execDSigTest "merlin-xmldsig-twenty-three/signature-enveloping-hmac-sha1" \
    "--hmackey keys/hmackey.bin" \
    "--hmackey keys/hmackey.bin" \
    "--hmackey keys/hmackey.bin" 

execDSigTest "merlin-xmldsig-twenty-three/signature-enveloping-rsa" \
    " " \
    "--privkey keys/rsakey.pem" \
    " " 
    
execDSigTest "merlin-xmldsig-twenty-three/signature-external-b64-dsa" \
    " " \
    "--privkey keys/dsakey.pem" \
    " " 
    
execDSigTest "merlin-xmldsig-twenty-three/signature-external-dsa" \
    " " \
    "--privkey keys/dsakey.pem" \
    " " 

execDSigTest "merlin-xmldsig-twenty-three/signature-keyname" \
    "--pubkey:Lugh merlin-xmldsig-twenty-three/certs/lugh.key" \
    "--privkey:test-dsa keys/dsakey.pem" \
    "--privkey:test-dsa keys/dsakey.pem"

execDSigTest "merlin-xmldsig-twenty-three/signature-x509-crt" \
    "--trusted merlin-xmldsig-twenty-three/certs/ca.pem" \
    "--privkey keys/dsakey.pem,keys/dsacert.pem,keys/ca2cert.pem"\
    "--trusted keys/cacert.pem"

execDSigTest "merlin-xmldsig-twenty-three/signature-x509-sn" \
    "--trusted merlin-xmldsig-twenty-three/certs/ca.pem --untrusted merlin-xmldsig-twenty-three/certs/badb.pem" \
    "--privkey keys/dsakey.pem,keys/dsacert.pem,keys/ca2cert.pem"\
    "--trusted keys/cacert.pem"

execDSigTest "merlin-xmldsig-twenty-three/signature-x509-is" \
    "--trusted merlin-xmldsig-twenty-three/certs/ca.pem --untrusted merlin-xmldsig-twenty-three/certs/macha.pem" \
    "--privkey keys/dsakey.pem,keys/dsacert.pem,keys/ca2cert.pem"\
    "--trusted keys/cacert.pem"

execDSigTest "merlin-xmldsig-twenty-three/signature-x509-ski" \
    "--trusted merlin-xmldsig-twenty-three/certs/ca.pem --untrusted merlin-xmldsig-twenty-three/certs/nemain.pem" \
    "--privkey keys/dsakey.pem,keys/dsacert.pem,keys/ca2cert.pem"\
    "--trusted keys/cacert.pem"

execDSigTest "merlin-xmldsig-twenty-three/signature-retrievalmethod-rawx509crt" \
    "--trusted merlin-xmldsig-twenty-three/certs/ca.pem --untrusted merlin-xmldsig-twenty-three/certs/nemain.pem" \
    "--privkey keys/dsakey.pem"\
    "--trusted keys/cacert.pem --trusted keys/ca2cert.pem"
    
execDSigTest "merlin-xmldsig-twenty-three/signature" \
    "--trusted merlin-xmldsig-twenty-three/certs/merlin.pem" \
    "--privkey keys/dsakey.pem,keys/dsacert.pem,keys/ca2cert.pem" \
    "--trusted keys/cacert.pem --untrusted keys/ca2cert.pem"
    
execDSigTest "merlin-exc-c14n-one/exc-signature" \
    " " \
    "--privkey keys/dsakey.pem" \
    " " 
    
execDSigTest "aleksey-xmldsig-01/enveloping-dsa-x509chain" \
    "--trusted keys/cacert.pem --allowed x509" \
    "--privkey keys/dsakey.pem,keys/dsacert.pem,keys/ca2cert.pem" \
    "--trusted keys/cacert.pem --allowed x509"

execDSigTest "aleksey-xmldsig-01/enveloping-rsa-x509chain" \
    "--trusted keys/cacert.pem --allowed x509" \
    "--privkey keys/rsakey.pem,keys/rsacert.pem,keys/ca2cert.pem" \
    "--trusted keys/cacert.pem --allowed x509"

execDSigTest "aleksey-xmldsig-01/enveloping-hmac-ripemd160" \
    "--hmackey keys/hmackey.bin" \
    "--hmackey keys/hmackey.bin" \
    "--hmackey keys/hmackey.bin" 

execDSigTest "aleksey-xmldsig-01/enveloping-hmac-ripemd160-64" \
    "--hmackey keys/hmackey.bin" \
    "--hmackey keys/hmackey.bin" \
    "--hmackey keys/hmackey.bin" 

execDSigTest "aleksey-xmldsig-01/enveloping-hmac-md5" \
    "--hmackey keys/hmackey.bin" \
    "--hmackey keys/hmackey.bin" \
    "--hmackey keys/hmackey.bin" 

execDSigTest "aleksey-xmldsig-01/enveloping-hmac-md5-64" \
    "--hmackey keys/hmackey.bin" \
    "--hmackey keys/hmackey.bin" \
    "--hmackey keys/hmackey.bin" 

echo "--------- Negative Testing: next test MUST FAIL ----------"
execDSigTest "merlin-xmldsig-twenty-three/signature-x509-crt-crl" \
    "--trusted merlin-xmldsig-twenty-three/certs/ca.pem"
    
rm -rf $tmpfile
echo "--- testDSig finished" >> $logfile
echo "--- testDSig finished"
echo "--- detailed log is written to  $logfile" 



#merlin-xmldsig-twenty-three/signature-retrievalmethod-rawx509crt.xml
