#!/bin/sh 

topfolder=.
binfolder=../apps
timestamp=`date +%Y%m%d_%H%M%S` 
tmpfile=/tmp/testEnc.$timestamp-$$.tmp
logfile=/tmp/testEnc.$timestamp-$$.log
script="$0"
keysfile=$topfolder/keys.xml

if [ -n "$DEBUG_MEMORY" ] ; then 
    export VALGRIND="valgrind --leak-check=yes --show-reachable=yes --num-callers=16"
    export REPEAT=1
    export EXTRA_PARAMS="--repeat $REPEAT"
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

execEncTest() {    
    file=$topfolder/$1      
    echo $1
    echo $1 >>  $logfile 
    
    printf "    Decrypt existing document                            "
    rm -f $tmpfile

    echo "$binfolder/xmlsec decrypt $2 $file.xml" >>  $logfile 
    $VALGRIND $binfolder/xmlsec decrypt $EXTRA_PARAMS $2 $file.xml > $tmpfile 2>> $logfile
    if [ $? = 0 ]; then
	diff $file.data $tmpfile >> $logfile 2>> $logfile
	printRes 
    else 
	echo " Error"
    fi

    if [ -n "$3" ] ; then
	printf "    Encrypt document                                     "
	rm -f $tmpfile
	echo "$binfolder/xmlsec encrypt $3 $file.tmpl" >>  $logfile 
	$VALGRIND $binfolder/xmlsec encrypt $EXTRA_PARAMS $3 $file.tmpl > $tmpfile 2>> $logfile
	printRes
	
	if [ -n "$4" ] ; then 
	    if [ -z "$VALGRIND" ] ; then
	        printf "    Decrypt new document                                 "
		echo "$binfolder/xmlsec decrypt $4 $tmpfile" >>  $logfile 
	        $VALGRIND $binfolder/xmlsec decrypt $EXTRA_PARAMS $4 $tmpfile > $tmpfile.2 2>> $logfile
		if [ $? = 0 ]; then
		    diff $file.data $tmpfile.2 >> $logfile 2>> $logfile
		    printRes
    		else 
		    echo " Error"
		fi
	    fi
	fi
    fi
    rm -f $tmpfile $tmpfile.2
}

echo "--- testEnc started ($timestamp)"
echo "--- testEnc started ($timestamp)" >> $logfile

execEncTest "aleksey-xmlenc-01/enc-des3cbc-keyname" \
    "--keys keys/keys.xml" \
    "--keys keys.xml --binary aleksey-xmlenc-01/enc-des3cbc-keyname.data" \
    "--keys keys.xml"

execEncTest "aleksey-xmlenc-01/enc-aes128cbc-keyname" \
    "--keys keys/keys.xml" \
    "--keys keys.xml --binary aleksey-xmlenc-01/enc-aes128cbc-keyname.data" \
    "--keys keys.xml"

execEncTest "aleksey-xmlenc-01/enc-aes192cbc-keyname" \
    "--keys keys/keys.xml" \
    "--keys keys.xml --binary aleksey-xmlenc-01/enc-aes192cbc-keyname.data" \
    "--keys keys.xml"

execEncTest "aleksey-xmlenc-01/enc-aes256cbc-keyname" \
    "--keys keys/keys.xml" \
    "--keys keys.xml --binary aleksey-xmlenc-01/enc-aes256cbc-keyname.data" \
    "--keys keys.xml"

execEncTest "aleksey-xmlenc-01/enc-des3cbc-keyname-content" \
    "--keys keys/keys.xml" \
    "--keys keys.xml --xml aleksey-xmlenc-01/enc-des3cbc-keyname-content.data --node-id Test" \
    "--keys keys.xml"

execEncTest "aleksey-xmlenc-01/enc-des3cbc-keyname-element" \
    "--keys keys/keys.xml" \
    "--keys keys.xml --xml aleksey-xmlenc-01/enc-des3cbc-keyname-element.data --node-id Test" \
    "--keys keys.xml"

execEncTest "aleksey-xmlenc-01/enc-des3cbc-keyname-element-root" \
    "--keys keys/keys.xml" \
    "--keys keys.xml --xml aleksey-xmlenc-01/enc-des3cbc-keyname-element-root.data --node-id Test" \
    "--keys keys.xml"

execEncTest "aleksey-xmlenc-01/enc-des3cbc-aes192-keyname" \
    "--keys keys/keys.xml --allowed keyname,enc-key" \
    "--keys keys.xml  --session-key-des3  --binary aleksey-xmlenc-01/enc-des3cbc-aes192-keyname.data" \
    "--keys keys.xml"

# Merlin's tests
execEncTest "merlin-xmlenc-five/encrypt-data-aes128-cbc" \
    "--keys merlin-xmlenc-five/keys.xml" \
    "--keys merlin-xmlenc-five/keys.xml --binary merlin-xmlenc-five/encrypt-data-aes128-cbc.data" \
    "--keys merlin-xmlenc-five/keys.xml"
execEncTest "merlin-xmlenc-five/encrypt-content-tripledes-cbc" \
    "--keys merlin-xmlenc-five/keys.xml" \
    "--keys merlin-xmlenc-five/keys.xml --allowed keymanager,keyname --xml merlin-xmlenc-five/encrypt-content-tripledes-cbc.data --node-id Payment" \
    "--keys merlin-xmlenc-five/keys.xml"
execEncTest "merlin-xmlenc-five/encrypt-content-aes256-cbc-prop" \
    "--keys merlin-xmlenc-five/keys.xml" \
    "--keys merlin-xmlenc-five/keys.xml --allowed keymanager,keyname --xml merlin-xmlenc-five/encrypt-content-aes256-cbc-prop.data --node-id Payment" \
    "--keys merlin-xmlenc-five/keys.xml"
execEncTest "merlin-xmlenc-five/encrypt-element-aes192-cbc-ref" \
    "--keys merlin-xmlenc-five/keys.xml"
execEncTest "merlin-xmlenc-five/encrypt-element-aes128-cbc-rsa-1_5" \
    "--privkey merlin-xmlenc-five/rsapriv.pem" \
    "--keys merlin-xmlenc-five/keys.xml --session-key-aes128 --privkey merlin-xmlenc-five/rsapriv.pem --xml merlin-xmlenc-five/encrypt-element-aes128-cbc-rsa-1_5.data --node-id Purchase"  \
    "--privkey merlin-xmlenc-five/rsapriv.pem"
execEncTest "merlin-xmlenc-five/encrypt-data-tripledes-cbc-rsa-oaep-mgf1p" \
    "--privkey merlin-xmlenc-five/rsapriv.pem" \
    "--keys merlin-xmlenc-five/keys.xml --session-key-des3 --privkey merlin-xmlenc-five/rsapriv.pem --binary merlin-xmlenc-five/encrypt-data-tripledes-cbc-rsa-oaep-mgf1p.data"  \
    "--privkey merlin-xmlenc-five/rsapriv.pem"
execEncTest "merlin-xmlenc-five/encrypt-data-aes256-cbc-kw-tripledes" \
    "--keys merlin-xmlenc-five/keys.xml" \
    "--keys merlin-xmlenc-five/keys.xml --session-key-aes256 --binary merlin-xmlenc-five/encrypt-data-aes256-cbc-kw-tripledes.data" \
    "--keys merlin-xmlenc-five/keys.xml"
execEncTest "merlin-xmlenc-five/encrypt-content-aes128-cbc-kw-aes192" \
    "--keys merlin-xmlenc-five/keys.xml" \
    "--keys merlin-xmlenc-five/keys.xml --session-key-aes128 --node-name urn:example:po:PaymentInfo --xml merlin-xmlenc-five/encrypt-content-aes128-cbc-kw-aes192.data" \
    "--keys merlin-xmlenc-five/keys.xml"

execEncTest "merlin-xmlenc-five/encrypt-data-aes192-cbc-kw-aes256" \
    "--keys merlin-xmlenc-five/keys.xml" \
    "--keys merlin-xmlenc-five/keys.xml --session-key-aes192 --binary merlin-xmlenc-five/encrypt-data-aes192-cbc-kw-aes256.data" \
    "--keys merlin-xmlenc-five/keys.xml"

execEncTest "merlin-xmlenc-five/encrypt-element-tripledes-cbc-kw-aes128" \
    "--keys merlin-xmlenc-five/keys.xml" \
    "--keys merlin-xmlenc-five/keys.xml  --session-key-des3 --node-name urn:example:po:PaymentInfo --xml merlin-xmlenc-five/encrypt-element-tripledes-cbc-kw-aes128.data" \
    "--keys merlin-xmlenc-five/keys.xml"
        
execEncTest "merlin-xmlenc-five/encrypt-element-aes256-cbc-retrieved-kw-aes256" \
    "--keys merlin-xmlenc-five/keys.xml" 


#merlin-xmlenc-five/encrypt-element-aes256-cbc-carried-kw-aes256.xml
#merlin-xmlenc-five/decryption-transform-except.xml
#merlin-xmlenc-five/decryption-transform.xml

#merlin-xmlenc-five/encrypt-element-aes256-cbc-kw-aes256-dh-ripemd160.xml
#merlin-xmlenc-five/encrypt-content-aes192-cbc-dh-sha512.xml
#merlin-xmlenc-five/encrypt-data-tripledes-cbc-rsa-oaep-mgf1p-sha256.xml
#merlin-xmlenc-five/encsig-hmac-sha256-dh.xml
#merlin-xmlenc-five/encsig-hmac-sha256-kw-tripledes-dh.xml
#merlin-xmlenc-five/encsig-hmac-sha256-rsa-1_5.xml
#merlin-xmlenc-five/encsig-hmac-sha256-rsa-oaep-mgf1p.xml
#merlin-xmlenc-five/encsig-sha256-hmac-sha256-kw-aes128.xml
#merlin-xmlenc-five/encsig-sha384-hmac-sha384-kw-aes192.xml
#merlin-xmlenc-five/encsig-sha512-hmac-sha512-kw-aes256.xml

execEncTest "01-phaos-xmlenc-3/enc-element-3des-kt-rsa1_5" \
    "--keys 01-phaos-xmlenc-3/keys.xml" \
    "--keys 01-phaos-xmlenc-3/keys.xml --allowed keymanager,keyname --xml 01-phaos-xmlenc-3/enc-element-3des-kt-rsa1_5.data --node-name http://example.org/paymentv2:CreditCard"  \
    "--keys 01-phaos-xmlenc-3/keys.xml"

execEncTest "01-phaos-xmlenc-3/enc-element-3des-kt-rsa_oaep_sha1" \
    "--keys 01-phaos-xmlenc-3/keys.xml" \
    "--keys 01-phaos-xmlenc-3/keys.xml --allowed keymanager,keyname --xml 01-phaos-xmlenc-3/enc-element-3des-kt-rsa_oaep_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
    "--keys 01-phaos-xmlenc-3/keys.xml"

execEncTest "01-phaos-xmlenc-3/enc-content-aes256-kt-rsa1_5" \
    "--keys 01-phaos-xmlenc-3/keys.xml" \
    "--keys 01-phaos-xmlenc-3/keys.xml --allowed keymanager,keyname --xml 01-phaos-xmlenc-3/enc-content-aes256-kt-rsa1_5.data --node-name http://example.org/paymentv2:CreditCard"  \
    "--keys 01-phaos-xmlenc-3/keys.xml"

execEncTest "01-phaos-xmlenc-3/enc-element-aes128-kt-rsa1_5" \
    "--keys 01-phaos-xmlenc-3/keys.xml" \
    "--keys 01-phaos-xmlenc-3/keys.xml --allowed keymanager,keyname --xml 01-phaos-xmlenc-3/enc-element-aes128-kt-rsa1_5.data --node-name http://example.org/paymentv2:CreditCard"  \
    "--keys 01-phaos-xmlenc-3/keys.xml"

execEncTest "01-phaos-xmlenc-3/enc-element-aes128-kt-rsa_oaep_sha1" \
    "--keys 01-phaos-xmlenc-3/keys.xml" \
    "--keys 01-phaos-xmlenc-3/keys.xml --allowed keymanager,keyname --xml 01-phaos-xmlenc-3/enc-element-aes128-kt-rsa_oaep_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
    "--keys 01-phaos-xmlenc-3/keys.xml"

execEncTest "01-phaos-xmlenc-3/enc-element-aes192-kt-rsa_oaep_sha1" \
    "--keys 01-phaos-xmlenc-3/keys.xml" \
    "--keys 01-phaos-xmlenc-3/keys.xml --allowed keymanager,keyname --xml 01-phaos-xmlenc-3/enc-element-aes192-kt-rsa_oaep_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
    "--keys 01-phaos-xmlenc-3/keys.xml"

execEncTest "01-phaos-xmlenc-3/enc-text-aes192-kt-rsa1_5" \
    "--keys 01-phaos-xmlenc-3/keys.xml" \
    "--keys 01-phaos-xmlenc-3/keys.xml --allowed keymanager,keyname --xml 01-phaos-xmlenc-3/enc-text-aes192-kt-rsa1_5.data --node-name http://example.org/paymentv2:CreditCard"  \
    "--keys 01-phaos-xmlenc-3/keys.xml"

execEncTest "01-phaos-xmlenc-3/enc-text-aes256-kt-rsa_oaep_sha1" \
    "--keys 01-phaos-xmlenc-3/keys.xml" \
    "--keys 01-phaos-xmlenc-3/keys.xml --allowed keymanager,keyname --xml 01-phaos-xmlenc-3/enc-text-aes256-kt-rsa_oaep_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
    "--keys 01-phaos-xmlenc-3/keys.xml"

execEncTest "01-phaos-xmlenc-3/enc-element-3des-kw-3des" \
    "--keys 01-phaos-xmlenc-3/keys.xml" \
    "--keys 01-phaos-xmlenc-3/keys.xml --allowed keymanager,keyname --xml 01-phaos-xmlenc-3/enc-element-3des-kw-3des.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys 01-phaos-xmlenc-3/keys.xml" 

execEncTest "01-phaos-xmlenc-3/enc-content-aes128-kw-3des" \
    "--keys 01-phaos-xmlenc-3/keys.xml" \
    "--keys 01-phaos-xmlenc-3/keys.xml --allowed keymanager,keyname --xml 01-phaos-xmlenc-3/enc-content-aes128-kw-3des.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys 01-phaos-xmlenc-3/keys.xml" 


execEncTest "01-phaos-xmlenc-3/enc-element-aes128-kw-aes128" \
    "--keys 01-phaos-xmlenc-3/keys.xml" \
    "--keys 01-phaos-xmlenc-3/keys.xml --allowed keymanager,keyname --xml 01-phaos-xmlenc-3/enc-element-aes128-kw-aes128.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys 01-phaos-xmlenc-3/keys.xml" 

execEncTest "01-phaos-xmlenc-3/enc-element-aes128-kw-aes256" \
    "--keys 01-phaos-xmlenc-3/keys.xml" \
    "--keys 01-phaos-xmlenc-3/keys.xml --allowed keymanager,keyname --xml 01-phaos-xmlenc-3/enc-element-aes128-kw-aes256.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys 01-phaos-xmlenc-3/keys.xml" 

execEncTest "01-phaos-xmlenc-3/enc-content-3des-kw-aes192" \
    "--keys 01-phaos-xmlenc-3/keys.xml" \
    "--keys 01-phaos-xmlenc-3/keys.xml --allowed keymanager,keyname --xml 01-phaos-xmlenc-3/enc-content-3des-kw-aes192.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys 01-phaos-xmlenc-3/keys.xml" 

execEncTest "01-phaos-xmlenc-3/enc-content-aes192-kw-aes256" \
    "--keys 01-phaos-xmlenc-3/keys.xml" \
    "--keys 01-phaos-xmlenc-3/keys.xml --allowed keymanager,keyname --xml 01-phaos-xmlenc-3/enc-content-aes192-kw-aes256.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys 01-phaos-xmlenc-3/keys.xml" 

execEncTest "01-phaos-xmlenc-3/enc-element-aes192-kw-aes192" \
    "--keys 01-phaos-xmlenc-3/keys.xml" \
    "--keys 01-phaos-xmlenc-3/keys.xml --allowed keymanager,keyname --xml 01-phaos-xmlenc-3/enc-element-aes192-kw-aes192.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys 01-phaos-xmlenc-3/keys.xml" 

execEncTest "01-phaos-xmlenc-3/enc-element-aes256-kw-aes256" \
    "--keys 01-phaos-xmlenc-3/keys.xml" \
    "--keys 01-phaos-xmlenc-3/keys.xml --allowed keymanager,keyname --xml 01-phaos-xmlenc-3/enc-element-aes256-kw-aes256.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys 01-phaos-xmlenc-3/keys.xml" 

execEncTest "01-phaos-xmlenc-3/enc-text-3des-kw-aes256" \
    "--keys 01-phaos-xmlenc-3/keys.xml" \
    "--keys 01-phaos-xmlenc-3/keys.xml --allowed keymanager,keyname --xml 01-phaos-xmlenc-3/enc-text-3des-kw-aes256.data --node-name http://example.org/paymentv2:CreditCard"  \
    "--keys 01-phaos-xmlenc-3/keys.xml"

execEncTest "01-phaos-xmlenc-3/enc-text-aes128-kw-aes192" \
    "--keys 01-phaos-xmlenc-3/keys.xml" \
    "--keys 01-phaos-xmlenc-3/keys.xml --allowed keymanager,keyname --xml 01-phaos-xmlenc-3/enc-text-aes128-kw-aes192.data --node-name http://example.org/paymentv2:CreditCard"  \
    "--keys 01-phaos-xmlenc-3/keys.xml"


    
#01-phaos-xmlenc-3/enc-element-3des-ka-dh.xml
#01-phaos-xmlenc-3/enc-element-aes128-ka-dh.xml
#01-phaos-xmlenc-3/enc-element-aes192-ka-dh.xml
#01-phaos-xmlenc-3/enc-element-aes256-ka-dh.xml

#01-phaos-xmlenc-3/enc-element-3des-kt-rsa_oaep_sha256.xml
#01-phaos-xmlenc-3/enc-element-3des-kt-rsa_oaep_sha512.xml


echo "--------- Negative Testing: Following tests MUST FAIL ----------"
echo "--- detailed log is written to  $logfile" 
execEncTest "01-phaos-xmlenc-3/bad-alg-enc-element-aes128-kw-3des" \
    "--keys 01-phaos-xmlenc-3/keys.xml"

    
rm -rf $tmpfile
echo "--- testEnc finished" >> $logfile
echo "--- testEnc finished"
echo "--- detailed log is written to  $logfile" 

#more $logfile

