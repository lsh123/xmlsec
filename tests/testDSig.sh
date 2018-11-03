#!/bin/sh
#
# This script needs to be called from testrun.sh script
#

# Setup URL to files mapping for offline testing, if tests are run against online
# then some tests might fail.
if [ -z "$XMLSEC_TEST_ONLINE" ]; then
    url_map_xml_stylesheet_2005="--url-map:http://www.w3.org/TR/xml-stylesheet $topfolder/external-data/xml-stylesheet-2005"
    url_map_xml_stylesheet_b64_2005="--url-map:http://www.w3.org/Signature/2002/04/xml-stylesheet.b64 $topfolder/external-data/xml-stylesheet-2005.b64"
    url_map_xml_stylesheet_2018="--url-map:http://www.w3.org/TR/xml-stylesheet $topfolder/external-data/xml-stylesheet-2018"
    url_map_rfc3161="--url-map:http://www.ietf.org/rfc/rfc3161.txt $topfolder/external-data/rfc3161.txt"
else
    url_map_xml_stylesheet_2005=""
    url_map_xml_stylesheet_b64_2005=""
    url_map_xml_stylesheet_2018=""
    url_map_rfc3161=""
fi

##########################################################################
##########################################################################
##########################################################################
if [ -z "$XMLSEC_TEST_REPRODUCIBLE" ]; then
    echo "--- testDSig started for xmlsec-$crypto library ($timestamp)"
fi
echo "--- LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
echo "--- LTDL_LIBRARY_PATH=$LTDL_LIBRARY_PATH"
if [ -z "$XMLSEC_TEST_REPRODUCIBLE" ]; then
    echo "--- log file is $logfile"
fi
echo "--- testDSig started for xmlsec-$crypto library ($timestamp)" >> $logfile
echo "--- LD_LIBRARY_PATH=$LD_LIBRARY_PATH" >> $logfile
echo "--- LTDL_LIBRARY_PATH=$LTDL_LIBRARY_PATH" >> $logfile


##########################################################################
##########################################################################
##########################################################################
echo "--------- Positive Testing ----------"

##########################################################################
#
# xmldsig2ed-tests
#
# http://www.w3.org/TR/xmldsig2ed-tests/
#
##########################################################################

execDSigTest $res_success \
    "xmldsig2ed-tests" \
    "defCan-1" \
    "c14n11 sha1 hmac-sha1" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "xmldsig2ed-tests" \
    "defCan-2" \
    "c14n11 xslt xpath sha1 hmac-sha1" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin"

#
# differences in XSLT transform output, tbd
#
# execDSigTest $res_success \
#    "xmldsig2ed-tests" \
#    "defCan-3" \
#    "c14n11 xslt xpath sha1 hmac-sha1" \
#    "hmac" \
#    "--hmackey $topfolder/keys/hmackey.bin" \
#    "--hmackey $topfolder/keys/hmackey.bin" \
#    "--hmackey $topfolder/keys/hmackey.bin" 
#

execDSigTest $res_success \
    "xmldsig2ed-tests" \
    "xpointer-1-SUN" \
    "c14n11 xpointer sha1 hmac-sha1" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "xmldsig2ed-tests" \
    "xpointer-2-SUN" \
    "c14n11 xpointer sha1 hmac-sha1" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "xmldsig2ed-tests" \
    "xpointer-3-SUN" \
    "c14n11 xpointer sha1 hmac-sha1" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "xmldsig2ed-tests" \
    "xpointer-4-SUN" \
    "c14n11 xpointer sha1 hmac-sha1" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "xmldsig2ed-tests" \
    "xpointer-5-SUN" \
     "c14n11 xpointer sha1 hmac-sha1" \
     "hmac" \
     "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "xmldsig2ed-tests" \
    "xpointer-6-SUN" \
     "c14n11 xpointer sha1 hmac-sha1" \
     "hmac" \
     "--hmackey $topfolder/keys/hmackey.bin"

##########################################################################
#
# aleksey-xmldsig-01
#
##########################################################################
execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/signature-two-keynames" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "$priv_key_option:key2 $topfolder/keys/rsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2018" \
    "$priv_key_option:key2 $topfolder/keys/rsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2018" \
    "$priv_key_option:key2 $topfolder/keys/rsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2018"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-dsa-x509chain" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-rsa-x509chain" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/rsakey.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-md5-hmac-md5" \
    "md5 hmac-md5" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-md5-hmac-md5-64" \
    "md5 hmac-md5" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-ripemd160-hmac-ripemd160" \
    "ripemd160 hmac-ripemd160" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-ripemd160-hmac-ripemd160-64" \
    "ripemd160 hmac-ripemd160" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/xpointer-hmac" \
    "xpointer sha1 hmac-sha1" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha1-hmac-sha1" \
    "sha1 hmac-sha1" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha1-hmac-sha1-64" \
    "sha1 hmac-sha1" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha224-hmac-sha224" \
    "sha224 hmac-sha224" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha224-hmac-sha224-64" \
    "sha224 hmac-sha224" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha256-hmac-sha256" \
    "sha256 hmac-sha256" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha256-hmac-sha256-64" \
    "sha256 hmac-sha256" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha384-hmac-sha384" \
    "sha384 hmac-sha384" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha384-hmac-sha384-64" \
    "sha384 hmac-sha384" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha512-hmac-sha512" \
    "sha512 hmac-sha512" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha512-hmac-sha512-64" \
    "sha512 hmac-sha512" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-md5-rsa-md5" \
    "md5 rsa-md5" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/rsakey.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-ripemd160-rsa-ripemd160" \
    "ripemd160 rsa-ripemd160" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/rsakey.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha1-rsa-sha1" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/rsakey.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha224-rsa-sha224" \
    "sha224 rsa-sha224" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/rsakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha256-rsa-sha256" \
    "sha256 rsa-sha256" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/rsakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

if [ "z$crypto" = "zopenssl" -a "z$priv_key_suffix" != "z-win" ] ; then
    # At least openssl supports --privkey-der next to --pkcs12 on non-Windows,
    # so test that as well.
    execDSigTest $res_success \
        "" \
        "aleksey-xmldsig-01/enveloping-sha256-rsa-sha256-der" \
        "sha256 rsa-sha256" \
        "rsa x509" \
        "--pubkey-cert-$cert_format $topfolder/keys/rsacert.$cert_format" \
        "--privkey-$cert_format $topfolder/keys/rsakey$priv_key_suffix.$cert_format" \
        "--pubkey-cert-$cert_format $topfolder/keys/rsacert.$cert_format"
fi

execDSigTest $res_success \
    "aleksey-xmldsig-01" \
    "enveloping-sha256-rsa-sha256-relationship" \
    "sha256 rsa-sha256 relationship" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/rsakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha384-rsa-sha384" \
    "sha384 rsa-sha384" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha512-rsa-sha512" \
    "sha512 rsa-sha512" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha256-dsa2048-sha256" \
    "sha256 dsa-sha256" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/dsa2048key$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha256-dsa3072-sha256" \
    "sha256 dsa-sha256" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/dsa3072key$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha1-ecdsa-sha1" \
    "sha1 ecdsa-sha1" \
    "ecdsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha256-ecdsa-sha256" \
    "sha256 ecdsa-sha256" \
    "ecdsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha384-ecdsa-sha384" \
    "sha384 ecdsa-sha384" \
    "ecdsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha512-ecdsa-sha512" \
    "sha512 ecdsa-sha512" \
    "ecdsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

# MSCNG doesn't support signatures with removed leading zeros (e.g. from Java)
# https://github.com/lsh123/xmlsec/issues/228
if [ "z$crypto" != "zmscng" ] ; then
execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-ecdsa-java-bug" \
    "sha512 ecdsa-sha512" \
    "ecdsa x509" \
    "--trusted-$cert_format $topfolder/keys/enveloped-ecdsa-java-bug-cert.$cert_format --enabled-key-data x509"
fi

#
# To generate expired cert run the following command
# > xmlsec1 sign --pkcs12 tests/keys/expiredkey.p12 --pwd secret123 --output out.xml ./tests/aleksey-xmldsig-01/enveloping-expired-cert.tmpl
#
execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-expired-cert" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509 --verification-time 2014-05-24+00:00:00" 


execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/dtd-hmac-91" \
    "sha1 hmac-sha1" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin --dtd-file $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd" \
    "--hmackey $topfolder/keys/hmackey.bin --dtd-file $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd" \
    "--hmackey $topfolder/keys/hmackey.bin --dtd-file $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/x509data-test" \
    "xpath2 sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format" \
    "$priv_key_option $topfolder/keys/rsakey.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/x509data-sn-test" \
    "xpath2 sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format  --untrusted-$cert_format $topfolder/keys/rsacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/rsakey.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format  --untrusted-$cert_format $topfolder/keys/rsacert.$cert_format --enabled-key-data x509"

##########################################################################
#
# merlin-xmldsig-twenty-three
#
##########################################################################
execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-enveloped-dsa" \
    "enveloped-signature sha1 dsa-sha1" \
    "dsa" \
    " " \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret123" \
    " "

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-enveloping-dsa" \
    "sha1 dsa-sha1" \
    "dsa" \
    " " \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret123" \
    " "

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-enveloping-b64-dsa" \
    "base64 sha1 dsa-sha1" \
    "dsa" \
    " " \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret123" \
    " "

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-enveloping-hmac-sha1-40" \
    "sha1 hmac-sha1" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-enveloping-hmac-sha1" \
    "sha1 hmac-sha1" \
    "hmac" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey $topfolder/keys/hmackey.bin" 

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-enveloping-rsa" \
    "sha1 rsa-sha1" \
    "rsa" \
    " " \
    "$priv_key_option $topfolder/keys/rsakey.$priv_key_format --pwd secret123" \
    " "

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-external-b64-dsa" \
    "base64 sha1 dsa-sha1" \
    "dsa" \
    " $url_map_xml_stylesheet_b64_2005" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_b64_2005" \
    " $url_map_xml_stylesheet_b64_2005"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-external-dsa" \
    "sha1 dsa-sha1" \
    "dsa" \
    "$url_map_xml_stylesheet_2005" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2005" \
    " $url_map_xml_stylesheet_2005"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-keyname" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--pubkey-cert-$cert_format:Lugh $topfolder/merlin-xmldsig-twenty-three/certs/lugh-cert.$cert_format $url_map_xml_stylesheet_2005" \
    "$priv_key_option:test-dsa $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2005" \
    "$priv_key_option:test-dsa $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2005"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-x509-crt" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format --verification-time 2005-01-01+10:00:00 $url_map_xml_stylesheet_2005" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2005"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format $url_map_xml_stylesheet_2005"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-x509-sn" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format --untrusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/badb.$cert_format --verification-time 2005-01-01+10:00:00 $url_map_xml_stylesheet_2005" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2005"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format $url_map_xml_stylesheet_2005"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-x509-is" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format --untrusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/macha.$cert_format --verification-time 2005-01-01+10:00:00 $url_map_xml_stylesheet_2005" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2005"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format $url_map_xml_stylesheet_2005"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-x509-ski" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format --untrusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/nemain.$cert_format --verification-time 2005-01-01+10:00:00 $url_map_xml_stylesheet_2005" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2005"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format $url_map_xml_stylesheet_2005"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-retrievalmethod-rawx509crt" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format --untrusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/nemain.$cert_format --verification-time 2005-01-01+10:00:00 $url_map_xml_stylesheet_2005" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2005"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --trusted-$cert_format $topfolder/keys/ca2cert.$cert_format $url_map_xml_stylesheet_2005"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature" \
    "base64 xpath xslt enveloped-signature c14n-with-comments sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/merlin.$cert_format --verification-time 2005-01-01+10:00:00 $url_map_xml_stylesheet_2005 $url_map_xml_stylesheet_b64_2005" \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2005 $url_map_xml_stylesheet_b64_2005" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format $url_map_xml_stylesheet_2005 $url_map_xml_stylesheet_b64_2005"


##########################################################################
#
# merlin-xmlenc-five
#
# While the main operation is signature (and this is why we have these 
# tests here instead of testEnc.sh), these tests check the encryption
# key transport/wrapper algorightms
#
##########################################################################
execDSigTest $res_success \
    "" \
    "merlin-xmlenc-five/encsig-ripemd160-hmac-ripemd160-kw-tripledes" \
    "ripemd160 hmac-ripemd160 kw-tripledes" \
    "hmac des" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml $url_map_xml_stylesheet_2005" \
    "--session-key hmac-192 --keys-file $topfolder/merlin-xmlenc-five/keys.xml $url_map_xml_stylesheet_2005" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml $url_map_xml_stylesheet_2005" 

execDSigTest $res_success \
    "" \
    "merlin-xmlenc-five/encsig-sha256-hmac-sha256-kw-aes128" \
    "sha256 hmac-sha256 kw-aes128" \
    "hmac aes" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml $url_map_xml_stylesheet_2005" 

execDSigTest $res_success \
    "" \
    "merlin-xmlenc-five/encsig-sha384-hmac-sha384-kw-aes192" \
    "sha384 hmac-sha384 kw-aes192" \
    "hmac aes" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml $url_map_xml_stylesheet_2005"

execDSigTest $res_success \
    "" \
    "merlin-xmlenc-five/encsig-sha512-hmac-sha512-kw-aes256" \
    "sha512 hmac-sha512 kw-aes256" \
    "hmac aes" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml $url_map_xml_stylesheet_2005"

execDSigTest $res_success \
    "" \
    "merlin-xmlenc-five/encsig-hmac-sha256-rsa-1_5" \
    "sha1 hmac-sha256 rsa-1_5" \
    "hmac rsa" \
    "$priv_key_option $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret $url_map_xml_stylesheet_2005"

execDSigTest $res_success \
    "" \
    "merlin-xmlenc-five/encsig-hmac-sha256-rsa-oaep-mgf1p" \
    "sha1 hmac-sha256 rsa-oaep-mgf1p" \
    "hmac rsa" \
    "$priv_key_option $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret $url_map_xml_stylesheet_2005"



##########################################################################
#
# merlin-exc-c14n-one
#
##########################################################################
execDSigTest $res_success \
    "" \
    "merlin-exc-c14n-one/exc-signature" \
    "exc-c14n sha1 dsa-sha1" \
    "dsa" \
    " " \
    "$priv_key_option $topfolder/keys/dsakey.$priv_key_format --pwd secret123" \
    " "

execDSigTest $res_success \
    "" \
    "merlin-exc-c14n-one/exc-signature" \
    "exc-c14n sha1 dsa-sha1" \
    "dsa" \
    " "

##########################################################################
#
# merlin-c14n-three
#
##########################################################################

execDSigTest $res_success \
    "" \
    "merlin-c14n-three/signature" \
    "c14n c14n-with-comments exc-c14n exc-c14n-with-comments xpath sha1 dsa-sha1" \
    "dsa" \
    " "

##########################################################################
#
# merlin-xpath-filter2-three
#
##########################################################################

execDSigTest $res_success \
    "" \
    "merlin-xpath-filter2-three/sign-xfdl" \
    "enveloped-signature xpath2 sha1 dsa-sha1" \
    "dsa" \
    " "

execDSigTest $res_success \
    "" \
    "merlin-xpath-filter2-three/sign-spec" \
    "enveloped-signature xpath2 sha1 dsa-sha1" \
    "dsa" \
    " "
##########################################################################
#
# phaos-xmldsig-three
#
##########################################################################

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-big" \
    "base64 xslt xpath sha1 rsa-sha1" \
    "rsa x509" \
    "--pubkey-cert-$cert_format certs/rsa-cert.$cert_format $url_map_rfc3161" 

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-dsa-detached" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format certs/dsa-ca-cert.$cert_format --verification-time 2009-01-01+10:00:00 $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-dsa-enveloped" \
    "enveloped-signature sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format certs/dsa-ca-cert.$cert_format --verification-time 2009-01-01+10:00:00"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-dsa-enveloping" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format certs/dsa-ca-cert.$cert_format --verification-time 2009-01-01+10:00:00"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-dsa-manifest" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format certs/dsa-ca-cert.$cert_format --verification-time 2009-01-01+10:00:00 $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-hmac-md5-c14n-enveloping" \
    "md5 hmac-md5" \
    "hmac" \
    "--hmackey certs/hmackey.bin"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-hmac-sha1-40-c14n-comments-detached" \
    "c14n-with-comments sha1 hmac-sha1" \
    "hmac" \
    "--hmackey certs/hmackey.bin  $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-hmac-sha1-40-exclusive-c14n-comments-detached" \
    "exc-c14n-with-comments sha1 hmac-sha1" \
    "hmac" \
    "--hmackey certs/hmackey.bin $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-hmac-sha1-exclusive-c14n-comments-detached" \
    "exc-c14n-with-comments sha1 hmac-sha1" \
    "hmac" \
    "--hmackey certs/hmackey.bin  $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-hmac-sha1-exclusive-c14n-enveloped" \
    "enveloped-signature exc-c14n sha1 hmac-sha1" \
    "hmac" \
    "--hmackey certs/hmackey.bin"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-detached-b64-transform" \
    "base64 sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --X509-skip-strict-checks --verification-time 2009-01-01+10:00:00  $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-detached" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --X509-skip-strict-checks --verification-time 2009-01-01+10:00:00  $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-detached-xpath-transform" \
    "xpath sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --X509-skip-strict-checks --verification-time 2009-01-01+10:00:00  $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-detached-xslt-transform-retrieval-method" \
    "xslt sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --X509-skip-strict-checks --verification-time 2009-01-01+10:00:00  $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-detached-xslt-transform" \
    "xslt sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --X509-skip-strict-checks --verification-time 2009-01-01+10:00:00  $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-enveloped" \
    "enveloped-signature sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --X509-skip-strict-checks --verification-time 2009-01-01+10:00:00"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-enveloping" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --X509-skip-strict-checks --verification-time 2009-01-01+10:00:00"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-manifest-x509-data-cert-chain" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --X509-skip-strict-checks --verification-time 2009-01-01+10:00:00 $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-manifest-x509-data-cert" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --X509-skip-strict-checks --verification-time 2009-01-01+10:00:00 $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-manifest-x509-data-issuer-serial" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --untrusted-$cert_format certs/rsa-cert.$cert_format --X509-skip-strict-checks --verification-time 2009-01-01+10:00:00 $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-manifest-x509-data-ski" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --untrusted-$cert_format certs/rsa-cert.$cert_format --X509-skip-strict-checks --verification-time 2009-01-01+10:00:00 $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-manifest-x509-data-subject-name" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --untrusted-$cert_format certs/rsa-cert.$cert_format --X509-skip-strict-checks --verification-time 2009-01-01+10:00:00 $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-manifest" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --X509-skip-strict-checks --verification-time 2009-01-01+10:00:00 $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-xpath-transform-enveloped" \
    "enveloped-signature xpath sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --X509-skip-strict-checks --verification-time 2009-01-01+10:00:00"


##########################################################################
#
# test dynamic signature
#
##########################################################################
if [ -n "$XMLSEC_TEST_NAME" -a "$XMLSEC_TEST_NAME" = "dsig-dynamic" ]; then
echo "Dynamic signature template"
printf "    Create new signature                                 "
echo "$VALGRIND $xmlsec_app sign-tmpl $xmlsec_params --keys-file $keysfile --output $tmpfile" >> $logfile
$VALGRIND $xmlsec_app sign-tmpl $xmlsec_params --keys-file $keysfile --output $tmpfile >> $logfile 2>> $logfile
printRes $res_success $?
printf "    Verify new signature                                 "
echo "$VALGRIND $xmlsec_app verify --keys-file $keysfile $tmpfile" >> $logfile
$VALGRIND $xmlsec_app verify $xmlsec_params --keys-file $keysfile $tmpfile >> $logfile 2>> $logfile
printRes $res_success $?
fi


##########################################################################
##########################################################################
##########################################################################
echo "--------- These tests CAN FAIL (extra OS config required) ----------"
execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-gost" \
    "enveloped-signature gostr3411" \
    "gost2001" \
    "--trusted-$cert_format $topfolder/keys/gost2001ca.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format  --enabled-key-data x509 --verification-time 2007-01-01+10:00:00" \
    "" \
    ""


##########################################################################
##########################################################################
##########################################################################
echo "--------- Negative Testing ----------"
execDSigTest $res_fail \
    "" \
    "merlin-xmldsig-twenty-three/signature-x509-crt-crl" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--X509-skip-strict-checks --trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format $url_map_xml_stylesheet_2018"

execDSigTest $res_fail \
    "" \
    "aleksey-xmldsig-01/enveloping-expired-cert" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509 --verification-time 2014-05-25+00:00:00" 

execDSigTest $res_fail \
    "" \
    "aleksey-xmldsig-01/dtd-hmac-91" \
    "sha1 hmac-sha1" \
    "hmac" \
    "--enabled-reference-uris empty --hmackey $topfolder/keys/hmackey.bin --dtd-file $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd" 

execDSigTest $res_fail \
    "phaos-xmldsig-three" \
    "signature-rsa-detached-xslt-transform-bad-retrieval-method" \
    "xslt sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format $url_map_rfc3161"

execDSigTest $res_fail \
    "phaos-xmldsig-three" \
    "signature-rsa-enveloped-bad-digest-val" \
    "enveloped-signature sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

execDSigTest $res_fail \
    "phaos-xmldsig-three" \
    "signature-rsa-enveloped-bad-sig" \
    "enveloped-signature sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

execDSigTest $res_fail \
    "phaos-xmldsig-three" \
    "signature-rsa-manifest-x509-data-crl" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

# 'Verify existing signature' MUST fail here, as --trusted-... is not passed.
# If this passes, that's a bug. Note that we need to cleanup NSS certs DB
# since it automaticall stores trusted certs
if [ "z$crypto" = "znss" ] ;
then
    certutil  -D -n "$NSS_TEST_CERT_NICKNAME" -d "$crypto_config"
    if [ $? -ne 0 ]; then
        echo "--- FAILED TO DELETE TRUSTED TEST CERTIFICATE FROM NSS CERT DB. THE NEXT TEST MIGHT FAIL" >> $logfile
        echo "--- FAILED TO DELETE TRUSTED TEST CERTIFICATE FROM NSS CERT DB. THE NEXT TEST MIGHT FAIL"
    fi
fi

execDSigTest $res_fail \
    "aleksey-xmldsig-01" \
    "enveloping-sha256-rsa-sha256-verify" \
    "sha256 rsa-sha256" \
    "rsa x509" \
    "--enabled-key-data x509"

# This is the same, but due to --insecure it must pass.
# If this fails, that means avoiding the certificate verification doesn't
# happen correctly.
execDSigTest $res_success \
    "aleksey-xmldsig-01" \
    "enveloping-sha256-rsa-sha256-verify" \
    "sha256 rsa-sha256" \
    "rsa x509" \
    "--enabled-key-data x509 --insecure"

##########################################################################
##########################################################################
##########################################################################
echo "--- testDSig finished" >> $logfile
echo "--- testDSig finished"
if [ -z "$XMLSEC_TEST_REPRODUCIBLE" ]; then
    echo "--- detailed log is written to  $logfile"
fi

