#!/bin/sh 

OS_ARCH=`uname -o`

if [ "z$OS_ARCH" = "zCygwin" ] ; then
	topfolder=`cygpath -wa $2`
	xmlsec_app=`cygpath -a $3`
else
	topfolder=$2
	xmlsec_app=$3
fi
crypto=$1
file_format=$4

pub_key_format=$file_format
cert_format=$file_format
priv_key_option="--pkcs12"
priv_key_format="p12"

if [ "z$TMPFOLDER" = "z" ] ; then
    TMPFOLDER=/tmp
fi
timestamp=`date +%Y%m%d_%H%M%S` 
if [ "z$OS_ARCH" = "zCygwin" ] ; then
	tmpfile=`cygpath -wa $TMPFOLDER/testDSig.$timestamp-$$.tmp`
	logfile=`cygpath -wa $TMPFOLDER/testDSig.$timestamp-$$.log`
else
	tmpfile=$TMPFOLDER/testDSig.$timestamp-$$.tmp
	logfile=$TMPFOLDER/testDSig.$timestamp-$$.log
fi

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
    folder=$1
    file=$2
    req_transforms=$3
    params1=$4
    params2=$5
    params3=$6
    old_pwd=`pwd`    
    rm -f $tmpfile

    if [ -n "$folder" ] ; then 
	cd $topfolder/$folder        
        full_file=$file
	echo $folder/$file
	echo "Test: $folder/$file in folder " `pwd` >> $logfile
    else
	full_file=$topfolder/$file        
        echo $file 
	echo "Test: $folder/$file" >> $logfile
    fi

    if [ -n "$req_transforms" ] ; then
	printf "    Checking required transforms                         "
        echo "$xmlsec_app check-transforms $req_transforms" >> $logfile
	$xmlsec_app check-transforms $req_transforms >> $logfile 2>> $logfile
	res=$?
	if [ $res = 0 ]; then
    	    echo "   OK"	    
	else
	    echo " Skip"
	    cd $old_pwd
	    return
	fi
    fi

    
    printf "    Verify existing signature                            "
    echo "$xmlsec_app verify $xmlsec_params $params1 $full_file.xml" >> $logfile
    $VALGRIND $xmlsec_app verify $xmlsec_params $params1 $full_file.xml >> $logfile 2>> $logfile
    printRes $?

    if [ -n "$params2"  -a -z "$PERF_TEST" ] ; then
	printf "    Create new signature                                 "
	echo "$xmlsec_app sign $xmlsec_params $params2 --output $tmpfile $full_file.tmpl" >> $logfile
	$VALGRIND $xmlsec_app sign $xmlsec_params $params2 --output $tmpfile $full_file.tmpl >> $logfile 2>> $logfile
	printRes $?
	
	if [ -n "$params3" ] ; then 
	    if [ -z "$VALGRIND" ] ; then 
		printf "    Verify new signature                                 "
		echo "$xmlsec_app verify $xmlsec_params $params3 $tmpfile" >> $logfile
		$VALGRIND $xmlsec_app verify $xmlsec_params $params3 $tmpfile >> $logfile 2>> $logfile
		printRes $?
	    fi
	fi
    fi
    
    cd $old_pwd
}

echo "--- testDSig started for xmlsec-$crypto library ($timestamp)" 
echo "--- LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
echo "--- log file is $logfile"
echo "--- testDSig started for xmlsec-$crypto library ($timestamp)" >> $logfile
echo "--- LD_LIBRARY_PATH=$LD_LIBRARY_PATH" >> $logfile

##########################################################################
#
# xmldsig2ed-tests
#
# http://www.w3.org/TR/xmldsig2ed-tests/
#
##########################################################################

execDSigTest "xmldsig2ed-tests" "defCan-1" \
    "c14n11 sha1 hmac-sha1" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "xmldsig2ed-tests" "defCan-2" \
    "c14n11 xslt xpath sha1 hmac-sha1" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

#
# differences in XSLT transform output, tbd
# 
# execDSigTest "xmldsig2ed-tests" "defCan-3" \
#     "c14n11 xslt xpath sha1 hmac-sha1" \
#     "--hmackey $topfolder/keys/hmackey.bin" \
#     "--hmackey $topfolder/keys/hmackey.bin" \
#     "--hmackey $topfolder/keys/hmackey.bin" 
# 

execDSigTest "xmldsig2ed-tests" "xpointer-1-SUN" \
     "c14n11 xpointer sha1 hmac-sha1" \
     "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest "xmldsig2ed-tests" "xpointer-2-SUN" \
     "c14n11 xpointer sha1 hmac-sha1" \
     "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest "xmldsig2ed-tests" "xpointer-3-SUN" \
     "c14n11 xpointer sha1 hmac-sha1" \
     "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest "xmldsig2ed-tests" "xpointer-4-SUN" \
     "c14n11 xpointer sha1 hmac-sha1" \
     "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest "xmldsig2ed-tests" "xpointer-5-SUN" \
     "c14n11 xpointer sha1 hmac-sha1" \
     "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest "xmldsig2ed-tests" "xpointer-6-SUN" \
     "c14n11 xpointer sha1 hmac-sha1" \
     "--hmackey $topfolder/keys/hmackey.bin"

##########################################################################
#
# aleksey-xmldsig-01
#
##########################################################################

execDSigTest "" "aleksey-xmldsig-01/enveloping-dsa-x509chain" \
    "sha1 dsa-sha1" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest "" "aleksey-xmldsig-01/enveloping-rsa-x509chain" \
    "sha1 rsa-sha1" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/rsakey.$priv_key_format --pwd secret" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest "" "aleksey-xmldsig-01/enveloping-md5-hmac-md5" \
    "md5 hmac-md5" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "" "aleksey-xmldsig-01/enveloping-md5-hmac-md5-64" \
    "md5 hmac-md5" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "" "aleksey-xmldsig-01/enveloping-ripemd160-hmac-ripemd160" \
    "ripemd160 hmac-ripemd160" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "" "aleksey-xmldsig-01/enveloping-ripemd160-hmac-ripemd160-64" \
    "ripemd160 hmac-ripemd160" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "" "aleksey-xmldsig-01/xpointer-hmac" \
    "xpointer sha1 hmac-sha1" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "" "aleksey-xmldsig-01/enveloping-sha1-hmac-sha1" \
    "sha1 hmac-sha1" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "" "aleksey-xmldsig-01/enveloping-sha1-hmac-sha1-64" \
    "sha1 hmac-sha1" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "" "aleksey-xmldsig-01/enveloping-sha224-hmac-sha224" \
    "sha224 hmac-sha224" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "" "aleksey-xmldsig-01/enveloping-sha224-hmac-sha224-64" \
    "sha224 hmac-sha224" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "" "aleksey-xmldsig-01/enveloping-sha256-hmac-sha256" \
    "sha256 hmac-sha256" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "" "aleksey-xmldsig-01/enveloping-sha256-hmac-sha256-64" \
    "sha256 hmac-sha256" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "" "aleksey-xmldsig-01/enveloping-sha384-hmac-sha384" \
    "sha384 hmac-sha384" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "" "aleksey-xmldsig-01/enveloping-sha384-hmac-sha384-64" \
    "sha384 hmac-sha384" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "" "aleksey-xmldsig-01/enveloping-sha512-hmac-sha512" \
    "sha512 hmac-sha512" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "" "aleksey-xmldsig-01/enveloping-sha512-hmac-sha512-64" \
    "sha512 hmac-sha512" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "" "aleksey-xmldsig-01/enveloping-md5-rsa-md5" \
    "md5 rsa-md5" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/rsakey.$priv_key_format --pwd secret" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest "" "aleksey-xmldsig-01/enveloping-ripemd160-rsa-ripemd160" \
    "ripemd160 rsa-ripemd160" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/rsakey.$priv_key_format --pwd secret" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest "" "aleksey-xmldsig-01/enveloping-sha1-rsa-sha1" \
    "sha1 rsa-sha1" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/rsakey.$priv_key_format --pwd secret" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest "" "aleksey-xmldsig-01/enveloping-sha224-rsa-sha224" \
    "sha224 rsa-sha224" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/rsakey.$priv_key_format --pwd secret" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest "" "aleksey-xmldsig-01/enveloping-sha256-rsa-sha256" \
    "sha256 rsa-sha256" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/rsakey.$priv_key_format --pwd secret" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest "" "aleksey-xmldsig-01/enveloping-sha384-rsa-sha384" \
    "sha384 rsa-sha384" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest "" "aleksey-xmldsig-01/enveloping-sha512-rsa-sha512" \
    "sha512 rsa-sha512" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

#
# To generate expired cert run the following command
# > xmlsec1 sign --pkcs12 tests/keys/expiredkey.p12 --pwd secret --output out.xml ./tests/aleksey-xmldsig-01/enveloping-expired-cert.tmpl
#
execDSigTest "" "aleksey-xmldsig-01/enveloping-expired-cert" \
    "sha1 rsa-sha1" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509 --verification-time 2005-07-10+10:00:00" 


execDSigTest "" "aleksey-xmldsig-01/dtd-hmac-91" \
    "sha1 hmac-sha1" \
    "--hmackey $topfolder/keys/hmackey.bin --dtd-file $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd" \
    "--hmackey $topfolder/keys/hmackey.bin --dtd-file $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd" \
    "--hmackey $topfolder/keys/hmackey.bin --dtd-file $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd"

execDSigTest "" "aleksey-xmldsig-01/x509data-test" \
    "xpath2 sha1 rsa-sha1" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format" \
    "$priv_key_option tests/keys/rsakey.$priv_key_format --pwd secret" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format"

execDSigTest "" "aleksey-xmldsig-01/x509data-sn-test" \
    "xpath2 sha1 rsa-sha1" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format  --untrusted-$cert_format $topfolder/keys/rsacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option tests/keys/rsakey.$priv_key_format --pwd secret" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format  --untrusted-$cert_format $topfolder/keys/rsacert.$cert_format --enabled-key-data x509"

##########################################################################
#
# merlin-xmldsig-twenty-three
#
##########################################################################

execDSigTest "" "merlin-xmldsig-twenty-three/signature-enveloped-dsa" \
    "enveloped-signature sha1 dsa-sha1" \
    " " \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret" \
    " " 
    
execDSigTest "" "merlin-xmldsig-twenty-three/signature-enveloping-dsa" \
    "sha1 dsa-sha1" \
    " " \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret" \
    " " 
    
execDSigTest "" "merlin-xmldsig-twenty-three/signature-enveloping-b64-dsa" \
    "base64 sha1 dsa-sha1" \
    " " \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret" \
    " " 
    
execDSigTest "" "merlin-xmldsig-twenty-three/signature-enveloping-hmac-sha1-40" \
    "sha1 hmac-sha1" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 
    
execDSigTest "" "merlin-xmldsig-twenty-three/signature-enveloping-hmac-sha1" \
    "sha1 hmac-sha1" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest "" "merlin-xmldsig-twenty-three/signature-enveloping-rsa" \
    "sha1 rsa-sha1" \
    " " \
    "$priv_key_option $topfolder/keys/rsakey.$priv_key_format --pwd secret" \
    " " 
    
execDSigTest "" "merlin-xmldsig-twenty-three/signature-external-b64-dsa" \
    "base64 sha1 dsa-sha1" \
    " " \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret" \
    " " 
    
execDSigTest "" "merlin-xmldsig-twenty-three/signature-external-dsa" \
    "sha1 dsa-sha1" \
    " " \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret" \
    " " 

execDSigTest "" "merlin-xmldsig-twenty-three/signature-keyname" \
    "sha1 dsa-sha1" \
    "--pubkey-cert-$cert_format:Lugh $topfolder/merlin-xmldsig-twenty-three/certs/lugh-cert.$cert_format" \
    "$priv_key_option:test-dsa $topfolder/keys/dsakey.$priv_key_format --pwd secret" \
    "$priv_key_option:test-dsa $topfolder/keys/dsakey.$priv_key_format --pwd secret"

execDSigTest "" "merlin-xmldsig-twenty-three/signature-x509-crt" \
    "sha1 dsa-sha1" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format"

execDSigTest "" "merlin-xmldsig-twenty-three/signature-x509-sn" \
    "sha1 dsa-sha1" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format --untrusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/badb.$cert_format" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format"

execDSigTest "" "merlin-xmldsig-twenty-three/signature-x509-is" \
    "sha1 dsa-sha1" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format --untrusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/macha.$cert_format" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format"

execDSigTest "" "merlin-xmldsig-twenty-three/signature-x509-ski" \
    "sha1 dsa-sha1" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format --untrusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/nemain.$cert_format" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format"

execDSigTest "" "merlin-xmldsig-twenty-three/signature-retrievalmethod-rawx509crt" \
    "sha1 dsa-sha1" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format --untrusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/nemain.$cert_format" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --trusted-$cert_format $topfolder/keys/ca2cert.$cert_format"
    
execDSigTest "" "merlin-xmldsig-twenty-three/signature" \
    "base64 xpath enveloped-signature c14n-with-comments sha1 dsa-sha1" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/merlin.$cert_format" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format"

##########################################################################
#
# merlin-xmlenc-five
#
##########################################################################

execDSigTest "" "merlin-xmlenc-five/encsig-ripemd160-hmac-ripemd160-kw-tripledes" \
    "ripemd160 hmac-ripemd160 kw-tripledes" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" \
    "--session-key hmac-192 --keys-file $topfolder/merlin-xmlenc-five/keys.xml" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" 

execDSigTest "" "merlin-xmlenc-five/encsig-sha256-hmac-sha256-kw-aes128" \
    "sha256 hmac-sha256 kw-aes128" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" 

execDSigTest "" "merlin-xmlenc-five/encsig-sha384-hmac-sha384-kw-aes192" \
    "sha384 hmac-sha384 kw-aes192" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" 

execDSigTest "" "merlin-xmlenc-five/encsig-sha512-hmac-sha512-kw-aes256" \
    "sha512 hmac-sha512 kw-aes256" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" 

#merlin-xmlenc-five/encsig-hmac-sha256-rsa-1_5.xml
#merlin-xmlenc-five/encsig-hmac-sha256-rsa-oaep-mgf1p.xml

##########################################################################
#
# merlin-exc-c14n-one
#
##########################################################################
    
execDSigTest "" "merlin-exc-c14n-one/exc-signature" \
    "exc-c14n sha1 dsa-sha1" \
    " " \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret" \
    " " 
    
execDSigTest "" "merlin-exc-c14n-one/exc-signature" \
    "exc-c14n sha1 dsa-sha1" \
    " "

##########################################################################
#
# merlin-c14n-three
#
##########################################################################
    
execDSigTest "" "merlin-c14n-three/signature" \
    "c14n c14n-with-comments exc-c14n exc-c14n-with-comments xpath sha1 dsa-sha1" \
    " "
    
##########################################################################
#
# merlin-xpath-filter2-three
#
##########################################################################

execDSigTest "" "merlin-xpath-filter2-three/sign-xfdl" \
    "enveloped-signature xpath2 sha1 dsa-sha1" \
    ""

execDSigTest "" "merlin-xpath-filter2-three/sign-spec" \
    "enveloped-signature xpath2 sha1 dsa-sha1" \
    ""
##########################################################################
#
# phaos-xmldsig-three
#
##########################################################################

execDSigTest "phaos-xmldsig-three" "signature-big" \
    "base64 xslt xpath sha1 rsa-sha1" \
    "--pubkey-cert-$cert_format certs/rsa-cert.$cert_format" 

execDSigTest "phaos-xmldsig-three" "signature-dsa-detached" \
    "sha1 dsa-sha1" \
    "--trusted-$cert_format certs/dsa-ca-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-dsa-enveloped" \
    "enveloped-signature sha1 dsa-sha1" \
    "--trusted-$cert_format certs/dsa-ca-cert.$cert_format"
    
execDSigTest "phaos-xmldsig-three" "signature-dsa-enveloping" \
    "sha1 dsa-sha1" \
    "--trusted-$cert_format certs/dsa-ca-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-dsa-manifest" \
    "sha1 dsa-sha1" \
    "--trusted-$cert_format certs/dsa-ca-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-hmac-md5-c14n-enveloping" \
    "md5 hmac-md5" \
    "--hmackey certs/hmackey.bin"
    
execDSigTest "phaos-xmldsig-three" "signature-hmac-sha1-40-c14n-comments-detached" \
    "c14n-with-comments sha1 hmac-sha1" \
    "--hmackey certs/hmackey.bin"
    
execDSigTest "phaos-xmldsig-three" "signature-hmac-sha1-40-exclusive-c14n-comments-detached" \
    "exc-c14n-with-comments sha1 hmac-sha1" \
    "--hmackey certs/hmackey.bin"
    
execDSigTest "phaos-xmldsig-three" "signature-hmac-sha1-exclusive-c14n-comments-detached" \
    "exc-c14n-with-comments sha1 hmac-sha1" \
    "--hmackey certs/hmackey.bin"
    
execDSigTest "phaos-xmldsig-three" "signature-hmac-sha1-exclusive-c14n-enveloped" \
    "enveloped-signature exc-c14n sha1 hmac-sha1" \
    "--hmackey certs/hmackey.bin"

execDSigTest "phaos-xmldsig-three" "signature-rsa-detached-b64-transform" \
    "base64 sha1 rsa-sha1" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-rsa-detached" \
    "sha1 rsa-sha1" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-rsa-detached-xpath-transform" \
    "xpath sha1 rsa-sha1" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-rsa-detached-xslt-transform-retrieval-method" \
    "xslt sha1 rsa-sha1" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-rsa-detached-xslt-transform" \
    "xslt sha1 rsa-sha1" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-rsa-enveloped" \
    "enveloped-signature sha1 rsa-sha1" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-rsa-enveloping" \
    "sha1 rsa-sha1" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-rsa-manifest-x509-data-cert-chain" \
    "sha1 rsa-sha1" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-rsa-manifest-x509-data-cert" \
    "sha1 rsa-sha1" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-rsa-manifest-x509-data-issuer-serial" \
    "sha1 rsa-sha1" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --untrusted-$cert_format certs/rsa-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-rsa-manifest-x509-data-ski" \
    "sha1 rsa-sha1" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --untrusted-$cert_format certs/rsa-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-rsa-manifest-x509-data-subject-name" \
    "sha1 rsa-sha1" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --untrusted-$cert_format certs/rsa-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-rsa-manifest" \
    "sha1 rsa-sha1" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-rsa-xpath-transform-enveloped" \
    "enveloped-signature xpath sha1 rsa-sha1" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"


##########################################################################
#
# test dynamic signature
#
##########################################################################

echo "Dynamic signature template"
printf "    Create new signature                                 "
echo "$xmlsec_app sign-tmpl $xmlsec_params --keys-file $keysfile --output $tmpfile" >> $logfile
$VALGRIND $xmlsec_app sign-tmpl $xmlsec_params --keys-file $keysfile --output $tmpfile >> $logfile 2>> $logfile
printRes $?
printf "    Verify new signature                                 "
echo "$xmlsec_app verify --keys-file $keysfile $tmpfile" >> $logfile
$VALGRIND $xmlsec_app verify $xmlsec_params --keys-file $keysfile $tmpfile >> $logfile 2>> $logfile
printRes $?


echo "--------- These tests CAN FAIL (extra OS config required) ----------"
execDSigTest "" "aleksey-xmldsig-01/enveloped-gost" \
    "enveloped-signature gostr34102001-gostr3411 gostr3411" \
    "--trusted-$cert_format $topfolder/keys/gost2001ca.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format  --enabled-key-data x509" \
    "" \
    ""


echo "--------- Negative Testing: next test MUST FAIL ----------"
execDSigTest "" "merlin-xmldsig-twenty-three/signature-x509-crt-crl" \
    "sha1 rsa-sha1" \
    "--X509-skip-strict-checks --trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format"

execDSigTest "" "aleksey-xmldsig-01/enveloping-expired-cert" \
    "sha1 dsa-sha1" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" 

execDSigTest "" "aleksey-xmldsig-01/dtd-hmac-91" \
    "sha1 hmac-sha1" \
    "--enabled-reference-uris empty --hmackey $topfolder/keys/hmackey.bin --dtd-file $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd" 

execDSigTest "phaos-xmldsig-three" "signature-rsa-detached-xslt-transform-bad-retrieval-method" \
    "xslt sha1 rsa-sha1" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-rsa-enveloped-bad-digest-val" \
    "enveloped-signature sha1 rsa-sha1" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-rsa-enveloped-bad-sig" \
    "enveloped-signature sha1 rsa-sha1" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

execDSigTest "phaos-xmldsig-three" "signature-rsa-manifest-x509-data-crl" \
    "sha1 rsa-sha1" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

rm -rf $tmpfile

echo "--- testDSig finished" >> $logfile
echo "--- testDSig finished"
echo "--- detailed log is written to  $logfile" 

