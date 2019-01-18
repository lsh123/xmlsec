#!/bin/sh
#
# This script needs to be called from testrun.sh script
#

##########################################################################
##########################################################################
##########################################################################
if [ -z "$XMLSEC_TEST_REPRODUCIBLE" ]; then
    echo "--- testEnc started for xmlsec-$crypto library ($timestamp)"
fi
echo "--- LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
echo "--- LTDL_LIBRARY_PATH=$LTDL_LIBRARY_PATH"
if [ -z "$XMLSEC_TEST_REPRODUCIBLE" ]; then
    echo "--- log file is $logfile"
fi
echo "--- testEnc started for xmlsec-$crypto library ($timestamp)" >> $logfile
echo "--- LD_LIBRARY_PATH=$LD_LIBRARY_PATH" >> $logfile
echo "--- LTDL_LIBRARY_PATH=$LTDL_LIBRARY_PATH" >> $logfile

##########################################################################
##########################################################################
##########################################################################
echo "--------- Positive Testing ----------"

##########################################################################
#
# aleksey-xmlenc-01
#
##########################################################################

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-keyname" \
    "tripledes-cbc" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $keysfile --binary-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-keyname.data" \
    "--keys-file $keysfile"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-keyname2" \
    "tripledes-cbc" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $keysfile --binary-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-keyname2.data" \
    "--keys-file $keysfile"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes128cbc-keyname" \
    "aes128-cbc" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $keysfile --binary-data $topfolder/aleksey-xmlenc-01/enc-aes128cbc-keyname.data" \
    "--keys-file $keysfile"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes192cbc-keyname" \
    "aes192-cbc" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $keysfile --binary-data $topfolder/aleksey-xmlenc-01/enc-aes192cbc-keyname.data" \
    "--keys-file $keysfile"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes192cbc-keyname-ref" \
    "aes192-cbc" \
    "--keys-file $topfolder/keys/keys.xml"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes256cbc-keyname" \
    "aes256-cbc" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $keysfile --binary-data $topfolder/aleksey-xmlenc-01/enc-aes256cbc-keyname.data" \
    "--keys-file $keysfile"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-keyname-content" \
    "tripledes-cbc" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $keysfile --xml-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-keyname-content.data --node-id Test" \
    "--keys-file $keysfile"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-keyname-element" \
    "tripledes-cbc" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $keysfile --xml-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-keyname-element.data --node-id Test" \
    "--keys-file $keysfile"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-keyname-element-root" \
    "tripledes-cbc" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $keysfile --xml-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-keyname-element-root.data --node-id Test" \
    "--keys-file $keysfile"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-aes192-keyname" \
    "tripledes-cbc kw-aes192" \
    "--keys-file $topfolder/keys/keys.xml --enabled-key-data key-name,enc-key" \
    "--keys-file $keysfile  --session-key des-192  --binary-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-aes192-keyname.data" \
    "--keys-file $keysfile"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1-params" \
    "aes256-cbc rsa-oaep-mgf1p" \
    "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
    "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1-params.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

##########################################################################
#
# merlin-xmlenc-five
#
##########################################################################

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-data-aes128-cbc" \
    "aes128-cbc" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --binary-data $topfolder/merlin-xmlenc-five/encrypt-data-aes128-cbc.data" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-content-tripledes-cbc" \
    "tripledes-cbc" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --enabled-key-data key-name --xml-data $topfolder/merlin-xmlenc-five/encrypt-content-tripledes-cbc.data --node-id Payment" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-content-aes256-cbc-prop" \
    "aes256-cbc" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --enabled-key-data key-name --xml-data $topfolder/merlin-xmlenc-five/encrypt-content-aes256-cbc-prop.data --node-id Payment" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-element-aes192-cbc-ref" \
    "aes192-cbc" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-element-aes128-cbc-rsa-1_5" \
    "aes128-cbc rsa-1_5" \
    "$priv_key_option $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --session-key aes-128 $priv_key_option $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --xml-data $topfolder/merlin-xmlenc-five/encrypt-element-aes128-cbc-rsa-1_5.data --node-id Purchase --pwd secret"  \
    "$priv_key_option $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-data-tripledes-cbc-rsa-oaep-mgf1p" \
    "tripledes-cbc rsa-oaep-mgf1p" \
    "$priv_key_option $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --session-key des-192 $priv_key_option $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --binary-data $topfolder/merlin-xmlenc-five/encrypt-data-tripledes-cbc-rsa-oaep-mgf1p.data --pwd secret"  \
    "$priv_key_option $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-data-aes256-cbc-kw-tripledes" \
    "aes256-cbc kw-tripledes" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --session-key aes-256 --binary-data $topfolder/merlin-xmlenc-five/encrypt-data-aes256-cbc-kw-tripledes.data" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-content-aes128-cbc-kw-aes192" \
    "aes128-cbc kw-aes192" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --session-key aes-128 --node-name urn:example:po:PaymentInfo --xml-data $topfolder/merlin-xmlenc-five/encrypt-content-aes128-cbc-kw-aes192.data" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-data-aes192-cbc-kw-aes256" \
    "aes192-cbc kw-aes256" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --session-key aes-192 --binary-data $topfolder/merlin-xmlenc-five/encrypt-data-aes192-cbc-kw-aes256.data" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-element-tripledes-cbc-kw-aes128" \
    "tripledes-cbc kw-aes128" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml  --session-key des-192 --node-name urn:example:po:PaymentInfo --xml-data $topfolder/merlin-xmlenc-five/encrypt-element-tripledes-cbc-kw-aes128.data" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-element-aes256-cbc-retrieved-kw-aes256" \
    "aes256-cbc kw-aes256" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" 


#merlin-xmlenc-five/encrypt-data-tripledes-cbc-rsa-oaep-mgf1p-sha256.xml

#merlin-xmlenc-five/encrypt-element-aes256-cbc-carried-kw-aes256.xml
#merlin-xmlenc-five/decryption-transform-except.xml
#merlin-xmlenc-five/decryption-transform.xml

#merlin-xmlenc-five/encrypt-element-aes256-cbc-kw-aes256-dh-ripemd160.xml
#merlin-xmlenc-five/encrypt-content-aes192-cbc-dh-sha512.xml
#merlin-xmlenc-five/encsig-hmac-sha256-dh.xml
#merlin-xmlenc-five/encsig-hmac-sha256-kw-tripledes-dh.xml

##########################################################################
#
# 01-phaos-xmlenc-3
#
##########################################################################

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-3des-kt-rsa1_5" \
    "tripledes-cbc rsa-1_5" \
    "$priv_key_option $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
    "--session-key des-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-3des-kt-rsa1_5.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-3des-kt-rsa_oaep_sha1" \
    "tripledes-cbc rsa-oaep-mgf1p" \
    "$priv_key_option $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
    "--session-key des-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-3des-kt-rsa_oaep_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-aes128-kt-rsa1_5" \
    "aes128-cbc rsa-1_5" \
    "$priv_key_option $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
    "--session-key aes-128 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-aes128-kt-rsa1_5.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-aes128-kt-rsa_oaep_sha1" \
    "aes128-cbc rsa-oaep-mgf1p" \
    "$priv_key_option $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
    "--session-key aes-128 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-aes128-kt-rsa_oaep_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-aes192-kt-rsa_oaep_sha1" \
    "aes192-cbc rsa-oaep-mgf1p" \
    "$priv_key_option $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
    "--session-key aes-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-aes192-kt-rsa_oaep_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-text-aes192-kt-rsa1_5" \
    "aes192-cbc rsa-1_5" \
    "$priv_key_option $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
    "--session-key aes-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name --xml-data $topfolder/01-phaos-xmlenc-3/enc-text-aes192-kt-rsa1_5.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-content-aes256-kt-rsa1_5" \
    "aes256-cbc rsa-1_5" \
    "$priv_key_option $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
    "--session-key aes-256 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name --xml-data $topfolder/01-phaos-xmlenc-3/enc-content-aes256-kt-rsa1_5.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-text-aes256-kt-rsa_oaep_sha1" \
    "aes256-cbc rsa-oaep-mgf1p" \
    "$priv_key_option $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
    "--session-key aes-256 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name --xml-data $topfolder/01-phaos-xmlenc-3/enc-text-aes256-kt-rsa_oaep_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-3des-kw-3des" \
    "tripledes-cbc kw-tripledes" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key des-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-3des-kw-3des.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" 

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-content-aes128-kw-3des" \
    "aes128-cbc kw-tripledes" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key aes-128 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name --xml-data $topfolder/01-phaos-xmlenc-3/enc-content-aes128-kw-3des.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" 

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-aes128-kw-aes128" \
    "aes128-cbc kw-aes128" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key aes-128 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-aes128-kw-aes128.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" 

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-aes128-kw-aes256" \
    "aes128-cbc kw-aes256" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key aes-128 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-aes128-kw-aes256.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" 

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-content-3des-kw-aes192" \
    "tripledes-cbc kw-aes192" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key des-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name --xml-data $topfolder/01-phaos-xmlenc-3/enc-content-3des-kw-aes192.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" 

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-content-aes192-kw-aes256" \
    "aes192-cbc kw-aes256" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key aes-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name --xml-data $topfolder/01-phaos-xmlenc-3/enc-content-aes192-kw-aes256.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" 

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-aes192-kw-aes192" \
    "aes192-cbc kw-aes192" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key aes-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-aes192-kw-aes192.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" 

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-aes256-kw-aes256" \
    "aes256-cbc kw-aes256" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key aes-256 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-aes256-kw-aes256.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" 

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-text-3des-kw-aes256" \
    "tripledes-cbc kw-aes256" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key des-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name --xml-data $topfolder/01-phaos-xmlenc-3/enc-text-3des-kw-aes256.data --node-name http://example.org/paymentv2:CreditCard"  \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-text-aes128-kw-aes192" \
    "aes128-cbc kw-aes192" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key aes-128 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name --xml-data $topfolder/01-phaos-xmlenc-3/enc-text-aes128-kw-aes192.data --node-name http://example.org/paymentv2:CreditCard"  \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml"

#01-phaos-xmlenc-3/enc-element-3des-ka-dh.xml
#01-phaos-xmlenc-3/enc-element-aes128-ka-dh.xml
#01-phaos-xmlenc-3/enc-element-aes192-ka-dh.xml
#01-phaos-xmlenc-3/enc-element-aes256-ka-dh.xml

#01-phaos-xmlenc-3/enc-element-3des-kt-rsa_oaep_sha256.xml
#01-phaos-xmlenc-3/enc-element-3des-kt-rsa_oaep_sha512.xml


echo "--------- AES-GCM tests include both positive and negative tests  ----------"
if [ -z "$XMLSEC_TEST_REPRODUCIBLE" ]; then
    echo "--- detailed log is written to  $logfile"
fi
##########################################################################
#
# AES-GCM
#
# IV length=96, AAD length=0 and tag length=128
##########################################################################
aesgcm_key_lengths="128 192 256"
aesgcm_plaintext_lengths="104 128 256 408"
aesgcm_vectors="01 02 03 04 05 06 07 08 09 10 11 12 13 14 15"
for aesgcm_k_l in $aesgcm_key_lengths ; do 
    for aesgcm_pt_l in $aesgcm_plaintext_lengths ; do 
        for aesgcm_v in $aesgcm_vectors ; do 
            base_test_name="nist-aesgcm/aes${aesgcm_k_l}/aes${aesgcm_k_l}-gcm-96-${aesgcm_pt_l}-0-128-${aesgcm_v}"
            # If the corresponding *.data file is missing then we expect the test to fail 
            if [ -f "$topfolder/$base_test_name.xml" -a ! -f "$topfolder/$base_test_name.data" ] ; then
                execEncTest "$res_fail" \
                    "" \
                    "$base_test_name" \
                    "aes${aesgcm_k_l}-gcm" \
                    "--keys-file $topfolder/nist-aesgcm/keys-aes${aesgcm_k_l}-gcm.xml" \
                    "" \
                    ""
            else
                # generate binary file out of base64
                DECODE="-d"
                if [ "`uname`" = "Darwin" ]; then
		    DECODE="-D"
                fi
                cat "$topfolder/$base_test_name.data" | base64 $DECODE > $tmpfile.3
                execEncTest "$res_success" \
                    "" \
                    "$base_test_name" \
                    "aes${aesgcm_k_l}-gcm" \
                    "--keys-file $topfolder/nist-aesgcm/keys-aes${aesgcm_k_l}-gcm.xml" \
                    "--keys-file $topfolder/nist-aesgcm/keys-aes${aesgcm_k_l}-gcm.xml --binary-data $tmpfile.3" \
                    "--keys-file $topfolder/nist-aesgcm/keys-aes${aesgcm_k_l}-gcm.xml" \
		    "base64"
            fi
        done
    done
done


##########################################################################
#
# test dynamicencryption
#
##########################################################################
if [ -n "$XMLSEC_TEST_NAME" -a "$XMLSEC_TEST_NAME" = "enc-dynamic" ]; then
echo "Dynamic encryption template"
printf "    Encrypt template                                     "
echo "$VALGRIND $xmlsec_app encrypt-tmpl $xmlsec_params --keys-file $keysfile --output $tmpfile" >> $logfile
$VALGRIND $xmlsec_app encrypt-tmpl $xmlsec_params --keys-file $keysfile --output $tmpfile >> $logfile 2>> $logfile
printRes $res_success $?
printf "    Decrypt document                                     "
echo "$VALGRIND $xmlsec_app decrypt $xmlsec_params $keysfile $tmpfile" >> $logfile
$VALGRIND $xmlsec_app decrypt $xmlsec_params --keys-file $keysfile $tmpfile >> $logfile 2>> $logfile
printRes $res_success $?
fi


##########################################################################
##########################################################################
##########################################################################
echo "--------- Negative Testing: Following tests MUST FAIL ----------"
if [ -z "$XMLSEC_TEST_REPRODUCIBLE" ]; then
    echo "--- detailed log is written to  $logfile"
fi
execEncTest $res_fail \
    "" \
    "01-phaos-xmlenc-3/bad-alg-enc-element-aes128-kw-3des" \
    "" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml"

execEncTest $res_fail \
    "" \
    "aleksey-xmlenc-01/enc-aes192cbc-keyname-ref" \
    "" \
    "--keys-file $topfolder/keys/keys.xml --enabled-cipher-reference-uris empty" 

execEncTest $res_fail \
    "" \
    "01-phaos-xmlenc-3/enc-content-aes256-kt-rsa1_5" \
    "" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-retrieval-method-uris empty"

rm -rf $tmpfile

##########################################################################
##########################################################################
##########################################################################
echo "--- testEnc finished" >> $logfile
echo "--- testEnc finished"
if [ -z "$XMLSEC_TEST_REPRODUCIBLE" ]; then
    echo "--- detailed log is written to  $logfile"
fi

