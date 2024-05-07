#!/bin/sh
#
# This script needs to be called from testrun.sh script
#

# ensure this script is called from testrun.sh
if [ -z "$xmlsec_app" -o -z "$crypto_config_folder" ]; then
    echo "This script needs to be called from testrun.sh script"
    exit 1
fi

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
# xmldsig11-interop-2011 (https://www.w3.org/TR/2012/NOTE-xmldsig-core1-interop-20121113/)
#
##########################################################################

# HMAC
# None of the tests include KeyInfo so we use "--lax-key-search" for *any* hmac key
execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-hmac-sha1-truncated40" \
    "c14n sha1 hmac-sha1" \
    "" \
    "--lax-key-search --hmackey keys/hmackey.bin --hmac-min-out-len 40"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-hmac-sha1-truncated160" \
    "c14n sha1 hmac-sha1" \
    "" \
    "--lax-key-search --hmackey keys/hmackey.bin"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-hmac-sha224" \
    "c14n sha1 hmac-sha224" \
    "" \
    "--lax-key-search --hmackey keys/hmackey.bin"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-hmac-sha224" \
    "c14n sha1 hmac-sha224" \
    "" \
    "--lax-key-search --hmackey keys/hmackey.bin"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-hmac-sha256" \
    "c14n sha1 hmac-sha256" \
    "" \
    "--lax-key-search --hmackey keys/hmackey.bin"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-hmac-sha384" \
    "c14n sha1 hmac-sha384" \
    "" \
    "--lax-key-search --hmackey keys/hmackey.bin"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-hmac-sha512" \
    "c14n sha1 hmac-sha512" \
    "" \
    "--lax-key-search --hmackey keys/hmackey.bin"

# ECDSA

# Diabled tests with PublicKey X,Y components (RFC4050, not part XMLDSig 1.1 spec):
#   signature-enveloping-p256_sha1_4050.xml
#   signature-enveloping-p256_sha512_4050.xml
#   signature-enveloping-p384_sha384_4050.xml
#   signature-enveloping-p521_sha256_4050.xml
#   signature-enveloping-p256_sha256_4050.xml
#   signature-enveloping-p384_sha1_4050.xml
#   signature-enveloping-p384_sha512_4050.xml
#   signature-enveloping-p521_sha384_4050.xml
#   signature-enveloping-p256_sha384_4050.xml
#   signature-enveloping-p384_sha256_4050.xml
#   signature-enveloping-p521_sha1_4050.xml
#   signature-enveloping-p521_sha512_4050.xml

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-p256_sha1" \
    "c14n sha1 ecdsa-sha1" \
    "key-value ec" \
    "--enabled-key-data key-value,ec" \
    "--enabled-key-data key-name,key-value,ec $priv_key_option:key-p256 $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,ec"


execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-p256_sha224" \
    "c14n sha1 ecdsa-sha224" \
    "key-value ec" \
    "--enabled-key-data key-value,ec" \
    "--enabled-key-data key-name,key-value,ec $priv_key_option:key-p256 $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,ec"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-p256_sha256" \
    "c14n sha1 ecdsa-sha256" \
    "key-value ec" \
    "--enabled-key-data key-value,ec" \
    "--enabled-key-data key-name,key-value,ec $priv_key_option:key-p256 $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,ec"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-p256_sha384" \
    "c14n sha1 ecdsa-sha384" \
    "key-value ec" \
    "--enabled-key-data key-value,ec" \
    "--enabled-key-data key-name,key-value,ec $priv_key_option:key-p256 $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,ec"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-p256_sha512" \
    "c14n sha1 ecdsa-sha512" \
    "key-value ec" \
    "--enabled-key-data key-value,ec" \
    "--enabled-key-data key-name,key-value,ec $priv_key_option:key-p256 $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,ec"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-p384_sha1" \
    "c14n sha1 ecdsa-sha1" \
    "key-value ec" \
    "--enabled-key-data key-value,ec" \
    "--enabled-key-data key-name,key-value,ec $priv_key_option:key-p384 $topfolder/keys/ecdsa-secp384r1-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,ec"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-p384_sha224" \
    "c14n sha1 ecdsa-sha224" \
    "key-value ec" \
    "--enabled-key-data key-value,ec" \
    "--enabled-key-data key-name,key-value,ec $priv_key_option:key-p384 $topfolder/keys/ecdsa-secp384r1-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,ec"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-p384_sha256" \
    "c14n sha1 ecdsa-sha256" \
    "key-value ec" \
    "--enabled-key-data key-value,ec" \
    "--enabled-key-data key-name,key-value,ec $priv_key_option:key-p384 $topfolder/keys/ecdsa-secp384r1-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,ec"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-p384_sha384" \
    "c14n sha1 ecdsa-sha384" \
    "key-value ec" \
    "--enabled-key-data key-value,ec" \
    "--enabled-key-data key-name,key-value,ec $priv_key_option:key-p384 $topfolder/keys/ecdsa-secp384r1-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,ec"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-p384_sha512" \
    "c14n sha1 ecdsa-sha512" \
    "key-value ec" \
    "--enabled-key-data key-value,ec" \
    "--enabled-key-data key-name,key-value,ec $priv_key_option:key-p384 $topfolder/keys/ecdsa-secp384r1-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,ec"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-p521_sha1" \
    "c14n sha1 ecdsa-sha1" \
    "key-value ec" \
    "--enabled-key-data key-value,ec" \
    "--enabled-key-data key-name,key-value,ec $priv_key_option:key-p521 $topfolder/keys/ecdsa-secp521r1-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,ec"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-p521_sha224" \
    "c14n sha1 ecdsa-sha224" \
    "key-value ec" \
    "--enabled-key-data key-value,ec" \
    "--enabled-key-data key-name,key-value,ec $priv_key_option:key-p521 $topfolder/keys/ecdsa-secp521r1-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,ec"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-p521_sha256" \
    "c14n sha1 ecdsa-sha256" \
    "key-value ec" \
    "--enabled-key-data key-value,ec" \
    "--enabled-key-data key-name,key-value,ec $priv_key_option:key-p521 $topfolder/keys/ecdsa-secp521r1-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,ec"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-p521_sha384" \
    "c14n sha1 ecdsa-sha384" \
    "key-value ec" \
    "--enabled-key-data key-value,ec" \
    "--enabled-key-data key-name,key-value,ec $priv_key_option:key-p521 $topfolder/keys/ecdsa-secp521r1-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,ec"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-p521_sha512" \
    "c14n sha1 ecdsa-sha512" \
    "key-value ec" \
    "--enabled-key-data key-value,ec" \
    "--enabled-key-data key-name,key-value,ec $priv_key_option:key-p521 $topfolder/keys/ecdsa-secp521r1-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,ec"

# RSA
execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-rsa-sha224" \
    "c14n sha1 rsa-sha224" \
    "rsa" \
    "--enabled-key-data key-value,rsa"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-rsa-sha256" \
    "c14n sha1 rsa-sha256" \
    "rsa" \
    "--enabled-key-data key-value,rsa"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-rsa_sha384" \
    "c14n sha1 rsa-sha256" \
    "rsa" \
    "--enabled-key-data key-value,rsa"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-rsa_sha512" \
    "c14n sha1 rsa-sha512" \
    "rsa" \
    "--enabled-key-data key-value,rsa"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-sha224-rsa_sha256" \
    "c14n sha224 rsa-sha256" \
    "rsa" \
    "--enabled-key-data key-value,rsa"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-sha256-rsa-sha256" \
    "c14n sha256 rsa-sha256" \
    "rsa" \
    "--enabled-key-data key-value,rsa"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-sha384-rsa_sha256" \
    "c14n sha384 rsa-sha256" \
    "rsa" \
    "--enabled-key-data key-value,rsa"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-sha512-rsa_sha256" \
    "c14n sha512 rsa-sha256" \
    "rsa" \
    "--enabled-key-data key-value,rsa"

# KeyInfoReference
execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-keyinforeference-rsa" \
    "c14n sha256 rsa-sha256" \
    "key-info-reference key-name key-value rsa" \
    "--enabled-key-data key-info-reference,key-name,key-value,rsa" \
    "$priv_key_option:largersakey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-info-reference,key-name,rsa $pub_key_option:largersakey $topfolder/keys/largersapubkey$pub_key_suffix.$pub_key_format"

# DEREncodedKeyValue
execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-derencoded-rsa" \
    "c14n sha256 rsa-sha256" \
    "der-encoded-key-value rsa" \
    "--enabled-key-data der-encoded-key-value,rsa" \
    "--enabled-key-data der-encoded-key-value,key-name,rsa $priv_key_option:largersakey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--enabled-key-data der-encoded-key-value,rsa"

execDSigTest $res_success \
    "xmldsig11-interop-2012" \
    "signature-enveloping-derencoded-ec" \
    "c14n sha256 ecdsa-sha256" \
    "der-encoded-key-value ec" \
    "--enabled-key-data der-encoded-key-value,ec" \
    "--enabled-key-data der-encoded-key-value,key-name,ec $priv_key_option:secp256r1 $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data der-encoded-key-value,ec"


# Only OpenSSL / NSS / GnuTLS currently has capability to lookup the certs/keys using X509 data
if [ "z$crypto" = "zopenssl" -o "z$crypto" = "znss" -o "z$crypto" = "zgnutls" ] ; then
    execDSigTest $res_success \
        "xmldsig11-interop-2012" \
        "signature-enveloping-x509digest-rsa" \
        "c14n sha256 rsa-sha256" \
        "x509" \
        "--enabled-key-data x509 --pubkey-cert-der ./keys/rsa-key.crt" \
        "--enabled-key-data x509 --pkcs12 $topfolder/keys/largersakey.p12 --pwd secret123" \
        "--enabled-key-data x509 --pubkey-cert-der $topfolder/keys/largersacert.der"
fi


##########################################################################
#
# xmldsig2ed-tests
#
# http://www.w3.org/TR/xmldsig2ed-tests/
#
# No KeyInfo so use --lax-key-search option
#
##########################################################################

execDSigTest $res_success \
    "xmldsig2ed-tests" \
    "defCan-1" \
    "c14n11 sha1 hmac-sha1" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "xmldsig2ed-tests" \
    "defCan-2" \
    "c14n11 xslt xpath sha1 hmac-sha1" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

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
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "xmldsig2ed-tests" \
    "xpointer-2-SUN" \
    "c14n11 xpointer sha1 hmac-sha1" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "xmldsig2ed-tests" \
    "xpointer-3-SUN" \
    "c14n11 xpointer sha1 hmac-sha1" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "xmldsig2ed-tests" \
    "xpointer-4-SUN" \
    "c14n11 xpointer sha1 hmac-sha1" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "xmldsig2ed-tests" \
    "xpointer-5-SUN" \
     "c14n11 xpointer sha1 hmac-sha1" \
     "hmac" \
     "--lax-key-search --hmackey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "xmldsig2ed-tests" \
    "xpointer-6-SUN" \
     "c14n11 xpointer sha1 hmac-sha1" \
     "hmac" \
     "--lax-key-search --hmackey $topfolder/keys/hmackey.bin"

##########################################################################
#
# aleksey-xmldsig-01
#
##########################################################################

# Only OpenSSL / NSS / GnuTLS currently has capability to lookup the certs/keys using X509 data
# These tests verify certificates lookup, keys lookup is tested in XMLEnc.sh
if [ "z$crypto" = "zopenssl" -o "z$crypto" = "znss" -o "z$crypto" = "zgnutls" ] ; then
    execDSigTest $res_success \
        "" \
        "aleksey-xmldsig-01/enveloped-x509-subjectname" \
        "sha512 rsa-sha512" \
        "rsa x509" \
        "--untrusted-$cert_format $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
        "$priv_key_option $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
        "--untrusted-$cert_format $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

    execDSigTest $res_success \
        "" \
        "aleksey-xmldsig-01/enveloped-x509-issuerserial" \
        "sha512 rsa-sha512" \
        "rsa x509" \
        "--untrusted-$cert_format $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
        "$priv_key_option $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
        "--untrusted-$cert_format $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

    execDSigTest $res_success \
        "" \
        "aleksey-xmldsig-01/enveloped-x509-ski" \
        "sha512 rsa-sha512" \
        "rsa x509" \
        "--untrusted-$cert_format $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
        "$priv_key_option $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
        "--untrusted-$cert_format $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

    execDSigTest $res_success \
        "" \
        "aleksey-xmldsig-01/enveloped-x509-digest-sha1" \
        "sha1 rsa-sha1" \
        "rsa x509" \
        "--untrusted-$cert_format $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
        "$priv_key_option $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
        "--untrusted-$cert_format $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

    execDSigTest $res_success \
        "" \
        "aleksey-xmldsig-01/enveloped-x509-digest-sha224" \
        "sha224 rsa-sha224" \
        "rsa x509" \
        "--untrusted-$cert_format $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
        "$priv_key_option $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
        "--untrusted-$cert_format $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

    execDSigTest $res_success \
        "" \
        "aleksey-xmldsig-01/enveloped-x509-digest-sha256" \
        "sha256 rsa-sha256" \
        "rsa x509" \
        "--untrusted-$cert_format $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
        "$priv_key_option $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
        "--untrusted-$cert_format $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

    execDSigTest $res_success \
        "" \
        "aleksey-xmldsig-01/enveloped-x509-digest-sha384" \
        "sha384 rsa-sha384" \
        "rsa x509" \
        "--untrusted-$cert_format $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
        "$priv_key_option $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
        "--untrusted-$cert_format $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

    execDSigTest $res_success \
        "" \
        "aleksey-xmldsig-01/enveloped-x509-digest-sha512" \
        "sha512 rsa-sha512" \
        "rsa x509" \
        "--untrusted-$cert_format $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
        "$priv_key_option $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
        "--untrusted-$cert_format $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

fi

# MSCng only supports SHA1 as cert digests and cannot lookup the key
if [ "z$crypto" = "zmscng" ] ; then
    execDSigTest $res_success \
        "" \
        "aleksey-xmldsig-01/enveloped-x509-digest-sha1" \
        "sha1 rsa-sha1" \
        "rsa x509" \
        "--untrusted-$cert_format $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
        "--lax-key-search $priv_key_option $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
        "--untrusted-$cert_format $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"
fi

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
    "$priv_key_option:mykey $topfolder/keys/dsakey.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-rsa-x509chain" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/rsakey.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-md5-hmac-md5" \
    "md5 hmac-md5" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-md5-hmac-md5-64" \
    "md5 hmac-md5" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-ripemd160-hmac-ripemd160" \
    "ripemd160 hmac-ripemd160" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-ripemd160-hmac-ripemd160-64" \
    "ripemd160 hmac-ripemd160" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/xpointer-hmac" \
    "xpointer sha1 hmac-sha1" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha1-hmac-sha1" \
    "sha1 hmac-sha1" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha1-hmac-sha1-64" \
    "sha1 hmac-sha1" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha224-hmac-sha224" \
    "sha224 hmac-sha224" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha224-hmac-sha224-64" \
    "sha224 hmac-sha224" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha256-hmac-sha256" \
    "sha256 hmac-sha256" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha256-hmac-sha256-64" \
    "sha256 hmac-sha256" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha384-hmac-sha384" \
    "sha384 hmac-sha384" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha384-hmac-sha384-64" \
    "sha384 hmac-sha384" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha512-hmac-sha512" \
    "sha512 hmac-sha512" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha512-hmac-sha512-64" \
    "sha512 hmac-sha512" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-md5-rsa-md5" \
    "md5 rsa-md5" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/rsakey.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-ripemd160-rsa-ripemd160" \
    "ripemd160 rsa-ripemd160" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/rsakey.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha1-rsa-sha1" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/rsakey.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha224-rsa-sha224" \
    "sha224 rsa-sha224" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/rsakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha256-rsa-sha256" \
    "sha256 rsa-sha256" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/rsakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "aleksey-xmldsig-01" \
    "enveloping-sha256-rsa-sha256-relationship" \
    "sha256 rsa-sha256 relationship" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/rsakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha384-rsa-sha384" \
    "sha384 rsa-sha384" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha512-rsa-sha512" \
    "sha512 rsa-sha512" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha224-rsa-pss-sha224" \
    "sha224 rsa-pss-sha224" \
    "rsa" \
    "$pub_key_option:largersakey $topfolder/keys/largersapubkey$pub_key_suffix.$pub_key_format" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "$pub_key_option:mykey $topfolder/keys/largersapubkey$pub_key_suffix.$pub_key_format"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha256-rsa-pss-sha256" \
    "sha256 rsa-pss-sha256" \
    "rsa" \
    "$pub_key_option:largersakey $topfolder/keys/largersapubkey$pub_key_suffix.$pub_key_format" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "$pub_key_option:mykey $topfolder/keys/largersapubkey$pub_key_suffix.$pub_key_format"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha384-rsa-pss-sha384" \
    "sha384 rsa-pss-sha384" \
    "rsa" \
    "$pub_key_option:largersakey $topfolder/keys/largersapubkey$pub_key_suffix.$pub_key_format" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "$pub_key_option:mykey $topfolder/keys/largersapubkey$pub_key_suffix.$pub_key_format"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha512-rsa-pss-sha512" \
    "sha512 rsa-pss-sha512" \
    "rsa" \
    "$pub_key_option:largersakey $topfolder/keys/largersapubkey$pub_key_suffix.$pub_key_format" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "$pub_key_option:mykey $topfolder/keys/largersapubkey$pub_key_suffix.$pub_key_format"


execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha3_224-rsa-pss-sha3_224" \
    "sha3-224 rsa-pss-sha3-224" \
    "rsa" \
    "$pub_key_option:largersakey $topfolder/keys/largersapubkey$pub_key_suffix.$pub_key_format" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "$pub_key_option:mykey $topfolder/keys/largersapubkey$pub_key_suffix.$pub_key_format"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha3_256-rsa-pss-sha3_256" \
    "sha3-256 rsa-pss-sha3-256" \
    "rsa" \
    "$pub_key_option:largersakey $topfolder/keys/largersapubkey$pub_key_suffix.$pub_key_format" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "$pub_key_option:mykey $topfolder/keys/largersapubkey$pub_key_suffix.$pub_key_format"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha3_384-rsa-pss-sha3_384" \
    "sha3-384 rsa-pss-sha3-384" \
    "rsa" \
    "$pub_key_option:largersakey $topfolder/keys/largersapubkey$pub_key_suffix.$pub_key_format" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "$pub_key_option:mykey $topfolder/keys/largersapubkey$pub_key_suffix.$pub_key_format"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha3_512-rsa-pss-sha3_512" \
    "sha3-512 rsa-pss-sha3-512" \
    "rsa" \
    "$pub_key_option:largersakey $topfolder/keys/largersapubkey$pub_key_suffix.$pub_key_format" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "$pub_key_option:mykey $topfolder/keys/largersapubkey$pub_key_suffix.$pub_key_format"


execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-rsa-pss-sha1" \
    "sha1 rsa-pss-sha1" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-rsa-pss-sha224" \
    "sha224 rsa-pss-sha224" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-rsa-pss-sha256" \
    "sha256 rsa-pss-sha256" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-rsa-pss-sha384" \
    "sha384 rsa-pss-sha384" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-rsa-pss-sha512" \
    "sha512 rsa-pss-sha512" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"


execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-rsa-pss-sha3_224" \
    "sha3-224 rsa-pss-sha3-224" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-rsa-pss-sha3_256" \
    "sha3-256 rsa-pss-sha3-256" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-rsa-pss-sha3_384" \
    "sha3-384 rsa-pss-sha3-384" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-rsa-pss-sha3_512" \
    "sha3-512 rsa-pss-sha3-512" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/largersakey$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"


execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha256-dsa2048-sha256" \
    "sha256 dsa-sha256" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/dsa2048key$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha256-dsa3072-sha256" \
    "sha256 dsa-sha256" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/dsa3072key$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha1-dsa-sha1" \
    "sha1 dsa-sha1" \
    "" \
    "$priv_key_option:DsaKey $topfolder/keys/dsakey.$priv_key_format --pwd secret123" \
    "$priv_key_option:dsakey $topfolder/keys/dsakey.$priv_key_format --pwd secret123" \
    "$priv_key_option:dsakey $topfolder/keys/dsakey.$priv_key_format --pwd secret123"


execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha1-ecdsa-sha1" \
    "sha1 ecdsa-sha1" \
    "" \
    "$priv_key_option:EcdsaSecp256r1 $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "$priv_key_option:TestEcdsaSecp256r1Key $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "$priv_key_option:TestEcdsaSecp256r1Key $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123"


execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-ripemd160-ecdsa-ripemd160" \
    "ripemd160 ecdsa-ripemd160" \
    "ec" \
    "$priv_key_option:mykey $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "$priv_key_option:mykey $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "$priv_key_option:mykey $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123"


execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha1-rsa-sha1" \
    "sha1 rsa-sha1" \
    "" \
    "$priv_key_option:mykey $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
    "$priv_key_option:largersakey $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
    "$priv_key_option:largersakey $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha224-ecdsa-sha224" \
    "sha224 ecdsa-sha224" \
    "ec" \
    "$pub_key_option:EcdsaSecp256r1 $topfolder/keys/ecdsa-secp256r1-pubkey.$pub_key_format" \
    "$priv_key_option:mykey $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "$pub_key_option:mykey $topfolder/keys/ecdsa-secp256r1-pubkey.$pub_key_format"


execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha256-ecdsa-sha256" \
    "sha256 ecdsa-sha256" \
    "ec" \
    "$pub_key_option:EcdsaSecp256r1 $topfolder/keys/ecdsa-secp256r1-pubkey.$pub_key_format" \
    "$priv_key_option:mykey $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "$pub_key_option:mykey $topfolder/keys/ecdsa-secp256r1-pubkey.$pub_key_format"


execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha384-ecdsa-sha384" \
    "sha384 ecdsa-sha384" \
    "ec" \
    "$pub_key_option:EcdsaSecp521r1 $topfolder/keys/ecdsa-secp521r1-pubkey.$pub_key_format" \
    "$priv_key_option:mykey $topfolder/keys/ecdsa-secp521r1-key.$priv_key_format --pwd secret123" \
    "$pub_key_option:mykey $topfolder/keys/ecdsa-secp521r1-pubkey.$pub_key_format"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha512-ecdsa-sha512" \
    "sha512 ecdsa-sha512" \
    "ec" \
    "$pub_key_option:EcdsaSecp521r1 $topfolder/keys/ecdsa-secp521r1-pubkey.$pub_key_format" \
    "$priv_key_option:mykey $topfolder/keys/ecdsa-secp521r1-key.$priv_key_format --pwd secret123" \
    "$pub_key_option:mykey $topfolder/keys/ecdsa-secp521r1-pubkey.$pub_key_format"


execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha3_224-ecdsa-sha3_224" \
    "sha3-224 ecdsa-sha3-224" \
    "ec" \
    "$pub_key_option:EcdsaSecp256r1 $topfolder/keys/ecdsa-secp256r1-pubkey.$pub_key_format" \
    "$priv_key_option:mykey $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "$pub_key_option:mykey $topfolder/keys/ecdsa-secp256r1-pubkey.$pub_key_format"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha3_256-ecdsa-sha3_256" \
    "sha3-256 ecdsa-sha3-256" \
    "ec" \
    "$pub_key_option:EcdsaSecp256r1 $topfolder/keys/ecdsa-secp256r1-pubkey.$pub_key_format" \
    "$priv_key_option:mykey $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "$pub_key_option:mykey $topfolder/keys/ecdsa-secp256r1-pubkey.$pub_key_format"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha3_384-ecdsa-sha3_384" \
    "sha3-384 ecdsa-sha3-384" \
    "ec" \
    "$pub_key_option:EcdsaSecp521r1 $topfolder/keys/ecdsa-secp521r1-pubkey.$pub_key_format" \
    "$priv_key_option:mykey $topfolder/keys/ecdsa-secp521r1-key.$priv_key_format --pwd secret123" \
    "$pub_key_option:mykey $topfolder/keys/ecdsa-secp521r1-pubkey.$pub_key_format"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-sha3_512-ecdsa-sha3_512" \
    "sha3-512 ecdsa-sha3-512" \
    "ec" \
    "$pub_key_option:EcdsaSecp521r1 $topfolder/keys/ecdsa-secp521r1-pubkey.$pub_key_format" \
    "$priv_key_option:mykey $topfolder/keys/ecdsa-secp521r1-key.$priv_key_format --pwd secret123" \
    "$pub_key_option:mykey $topfolder/keys/ecdsa-secp521r1-pubkey.$pub_key_format"


execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha1-ecdsa-sha1" \
    "sha1 ecdsa-sha1" \
    "ec x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha256-ecdsa-sha256" \
    "sha256 ecdsa-sha256" \
    "ec x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha384-ecdsa-sha384" \
    "sha384 ecdsa-sha384" \
    "ec x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/ecdsa-secp521r1-key.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-sha512-ecdsa-sha512" \
    "sha512 ecdsa-sha512" \
    "ec x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/ecdsa-secp521r1-key.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

# see issue https://github.com/lsh123/xmlsec/issues/228
execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-ecdsa-java-bug" \
    "sha512 ecdsa-sha512" \
    "ec x509" \
    "--trusted-$cert_format $topfolder/keys/enveloped-ecdsa-java-bug-cert.$cert_format --enabled-key-data x509 --verification-gmt-time 2019-01-01+00:00:00"


extra_message="DTD is present"
execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/dtd-hmac-91" \
    "sha1 hmac-sha1" \
    "hmac" \
    "--hmackey:name:KEY $topfolder/keys/hmackey.bin --dtd-file $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin --dtd-file $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin --dtd-file $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd"

extra_message="Negative test: missing DTD"
execDSigTest $res_fail \
    "" \
    "aleksey-xmldsig-01/dtd-hmac-91" \
    "sha1 hmac-sha1" \
    "hmac" \
    "--enabled-reference-uris empty --hmackey $topfolder/keys/hmackey.bin --dtd-file $topfolder/aleksey-xmldsig-01/dtd-hmac-91.dtd"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/x509data-test" \
    "xpath2 sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format" \
    "$priv_key_option:mykey $topfolder/keys/rsakey.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/x509data-sn-test" \
    "xpath2 sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format  --untrusted-$cert_format $topfolder/keys/rsacert.$cert_format --enabled-key-data x509" \
    "$priv_key_option:mykey $topfolder/keys/rsakey.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format  --untrusted-$cert_format $topfolder/keys/rsacert.$cert_format --enabled-key-data x509"


##########################################################################
##########################################################################
##########################################################################
echo "--------- Certificate verification testing ----------"

#
# To generate output with an expired cert run the following command
# > xmlsec1 sign --pkcs12 tests/keys/expiredkey.p12 --pwd secret123 --output out.xml ./tests/aleksey-xmldsig-01/enveloping-expired-cert.tmpl
#

# This should fail: expired cert
extra_message="Negative test: expired cert"
execDSigTest $res_fail \
    "" \
    "aleksey-xmldsig-01/enveloping-expired-cert" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509 --verification-gmt-time 2022-12-20+00:00:00"

# Expired cert but there is verification time overwrite
extra_message="Expired cert but there is verification timestamp overwrite"
execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloping-expired-cert" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509 --verification-gmt-time 2022-12-14+00:00:00"

# 'Verify existing signature' MUST fail here, as --trusted-... is not passed.
# If this passes, that's a bug. Note that we need to cleanup NSS certs DB
# since it automaticall stores trusted certs
extra_message="Missing trusted cert but there is --insecure bypass"
execDSigTest $res_fail \
    "aleksey-xmldsig-01" \
    "enveloping-sha256-rsa-sha256-verify" \
    "sha256 rsa-sha256" \
    "rsa x509" \
    "--enabled-key-data x509"

# This is the same, but due to --insecure it must pass.
# If this fails, that means avoiding the certificate verification doesn't
# happen correctly
extra_message="Negative test: missing trusted cert"
execDSigTest $res_success \
    "aleksey-xmldsig-01" \
    "enveloping-sha256-rsa-sha256-verify" \
    "sha256 rsa-sha256" \
    "rsa x509" \
    "--enabled-key-data x509 --insecure"

# Test was created using the following command:
# xmlsec1 sign --lax-key-search --privkey-pem tests/keys/rsakey.pem,tests/keys/rsacert.pem tests/aleksey-xmldsig-01/enveloped-x509-missing-cert.tmpl
#

# this should succeeed with both intermidiate and trusted certs provided
extra_message="Cert chaing is good"
execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-x509-missing-cert" \
    "sha256 rsa-sha256" \
    "x509" \
    "--untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

# this should succeeed too because we bypass all cert checks with --insecure mode
extra_message="Cert chain is missing but there is --insecure bypass"
execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-x509-missing-cert" \
    "sha256 rsa-sha256" \
    "x509" \
    "--insecure --enabled-key-data x509"

# this should fail: missing intermidiate cert (ca2cert)
extra_message="Negative test: Missing intermidiate cert"
execDSigTest $res_fail \
    "" \
    "aleksey-xmldsig-01/enveloped-x509-missing-cert" \
    "sha256 rsa-sha256" \
    "x509" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

# this should fail: wront trusted cert (largersacert)
extra_message="Negative test: Wront trusted cert"
execDSigTest $res_fail \
    "" \
    "aleksey-xmldsig-01/enveloped-x509-missing-cert" \
    "sha256 rsa-sha256" \
    "x509" \
    "--untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/largersacert.$cert_format --enabled-key-data x509"

# currently only openssl/gnutls/nss support loading CRL from the command line
# https://github.com/lsh123/xmlsec/issues/583
if [ "z$crypto" = "zopenssl" -o  "z$crypto" = "zgnutls" -o "z$crypto" = "znss" ] ; then
    # this should fail because there is a CRL for the cert used for signing
    extra_message="Negative test: CRL present"
    execDSigTest $res_fail \
        "" \
        "aleksey-xmldsig-01/enveloped-x509-missing-cert" \
        "sha256 rsa-sha256" \
        "x509" \
        "--untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --crl-$cert_format $topfolder/keys/rsacert-revoked-crl.$cert_format --enabled-key-data x509"

    # this should fail because while CRL is past due, it's still better than nothing
    extra_message="Negative test: CRL is past due"
    execDSigTest $res_fail \
        "" \
        "aleksey-xmldsig-01/enveloped-x509-missing-cert" \
        "sha256 rsa-sha256" \
        "x509" \
        "--verification-gmt-time 2023-05-01+00:00:00 --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --crl-$cert_format $topfolder/keys/rsacert-revoked-crl.$cert_format --enabled-key-data x509"

    # GnuTLS doesn't allow CRL verification by time (https://github.com/lsh123/xmlsec/issues/579)
    if [ "z$crypto" != "zgnutls" ] ; then
        # this should succeeed because CRL is not valid yet
        extra_message="CRL is not valid yet"
        execDSigTest $res_success \
            "" \
            "aleksey-xmldsig-01/enveloped-x509-missing-cert" \
            "sha256 rsa-sha256" \
            "x509" \
            "--verification-gmt-time 2023-03-01+00:00:00 --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --crl-$cert_format $topfolder/keys/rsacert-revoked-crl.$cert_format --enabled-key-data x509"
    fi

    # this should succeeed too because we bypass all cert checks with --insecure mode
    extra_message="CRL is present but there is --insecure bypass"
    execDSigTest $res_success \
        "" \
        "aleksey-xmldsig-01/enveloped-x509-missing-cert" \
        "sha256 rsa-sha256" \
        "x509" \
        "--insecure --crl-$cert_format $topfolder/keys/rsacert-revoked-crl.$cert_format --enabled-key-data x509"
fi


# only openssl, gnutls, nss, and mcng supports key verification
# https://github.com/lsh123/xmlsec/issues/587
if [ "z$crypto" = "zopenssl" -o  "z$crypto" = "zgnutls" -o "z$crypto" = "znss" -o "z$crypto" = "zmscng" ] ; then
    # this should succeeed because key verification is not requested (no --verify-keys option)
    extra_message="Successfully use key without verification"
    execDSigTest $res_success \
        "" \
        "aleksey-xmldsig-01/enveloped-sha1-rsa-sha1" \
        "sha1 rsa-sha1" \
        "x509" \
        "--pubkey-cert-$cert_format:mykey $topfolder/keys/largersacert.$cert_format --enabled-key-data key-name"

    # this should fail because key cannot be verified without certificates
    extra_message="Negative test: key cannot be verified"
    execDSigTest $res_fail \
        "" \
        "aleksey-xmldsig-01/enveloped-sha1-rsa-sha1" \
        "sha1 rsa-sha1" \
        "x509" \
        "--verify-keys --pubkey-cert-$cert_format:mykey $topfolder/keys/largersacert.$cert_format --enabled-key-data key-name"

    # this should fail because key cannot be verified at specified time
    extra_message="Negative test: key cannot be verified (cert is not yet valid)"
    execDSigTest $res_fail \
        "" \
        "aleksey-xmldsig-01/enveloped-sha1-rsa-sha1" \
        "sha1 rsa-sha1" \
        "x509" \
        "--verify-keys --verification-gmt-time 1980-01-01+00:00:00  --pubkey-cert-$cert_format:mykey  $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data key-name"

    # this should succeeed because key can be verified
    extra_message="Successfully verify key"
    execDSigTest $res_success \
        "" \
        "aleksey-xmldsig-01/enveloped-sha1-rsa-sha1" \
        "sha1 rsa-sha1" \
        "x509" \
        "--verify-keys --pubkey-cert-$cert_format:mykey  $topfolder/keys/largersacert.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format --trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data key-name"


fi

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
    "--enabled-key-data key-value,key-name,dsa" \
    "--enabled-key-data key-value,key-name,dsa $priv_key_option:mykey $topfolder/keys/dsakey.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,key-name,dsa"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-enveloping-dsa" \
    "sha1 dsa-sha1" \
    "dsa" \
    "--enabled-key-data key-value,key-name,dsa" \
    "--enabled-key-data key-value,key-name,dsa $priv_key_option:mykey $topfolder/keys/dsakey.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,key-name,dsa"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-enveloping-b64-dsa" \
    "base64 sha1 dsa-sha1" \
    "dsa" \
    "--enabled-key-data key-value,key-name,dsa" \
    "--enabled-key-data key-value,key-name,dsa $priv_key_option:mykey $topfolder/keys/dsakey.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,key-name,dsa"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-enveloping-hmac-sha1-40" \
    "sha1 hmac-sha1" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-enveloping-hmac-sha1" \
    "sha1 hmac-sha1" \
    "hmac" \
    "--lax-key-search --hmackey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin" \
    "--hmackey:mykey $topfolder/keys/hmackey.bin"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-enveloping-rsa" \
    "sha1 rsa-sha1" \
    "rsa" \
    "--enabled-key-data key-value,key-name,rsa" \
    "--enabled-key-data key-value,key-name,rsa $priv_key_option:mykey $topfolder/keys/rsakey.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,key-name,rsa"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-external-b64-dsa" \
    "base64 sha1 dsa-sha1" \
    "dsa" \
    "--enabled-key-data key-value,key-name,dsa $url_map_xml_stylesheet_b64_2005" \
    "--enabled-key-data key-value,key-name,dsa $priv_key_option:mykey $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_b64_2005" \
    "--enabled-key-data key-value,key-name,dsa $url_map_xml_stylesheet_b64_2005"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-external-dsa" \
    "sha1 dsa-sha1" \
    "dsa" \
    "--enabled-key-data key-value,key-name,dsa $url_map_xml_stylesheet_2005" \
    "--enabled-key-data key-value,key-name,dsa $priv_key_option:mykey $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2005" \
    "--enabled-key-data key-value,key-name,dsa $url_map_xml_stylesheet_2005"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-keyname" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--pubkey-cert-$cert_format:Lugh $topfolder/merlin-xmldsig-twenty-three/certs/lugh-cert.$cert_format $url_map_xml_stylesheet_2005" \
    "$priv_key_option:mykey $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2005" \
    "$priv_key_option:mykey $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2005"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-x509-crt" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format --verification-gmt-time 2005-01-01+10:00:00 $url_map_xml_stylesheet_2005" \
    "$priv_key_option:mykey $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2005"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format $url_map_xml_stylesheet_2005"

extra_message="Negative test: CRL is present"
execDSigTest $res_fail \
    "" \
    "merlin-xmldsig-twenty-three/signature-x509-crt-crl" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format $url_map_xml_stylesheet_2018"


execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-x509-sn" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format --untrusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/badb.$cert_format --verification-gmt-time 2005-01-01+10:00:00 $url_map_xml_stylesheet_2005" \
    "$priv_key_option:mykey $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2005"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format $url_map_xml_stylesheet_2005"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-x509-is" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format --untrusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/macha.$cert_format --verification-gmt-time 2005-01-01+10:00:00 $url_map_xml_stylesheet_2005" \
    "$priv_key_option:mykey $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2005"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format $url_map_xml_stylesheet_2005"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-x509-ski" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format --untrusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/nemain.$cert_format --verification-gmt-time 2005-01-01+10:00:00 $url_map_xml_stylesheet_2005" \
    "$priv_key_option:mykey $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2005"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format $url_map_xml_stylesheet_2005"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature-retrievalmethod-rawx509crt" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/ca.$cert_format --untrusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/nemain.$cert_format --verification-gmt-time 2005-01-01+10:00:00 $url_map_xml_stylesheet_2005" \
    "--lax-key-search $priv_key_option:mykey $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2005"\
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --trusted-$cert_format $topfolder/keys/ca2cert.$cert_format $url_map_xml_stylesheet_2005"

execDSigTest $res_success \
    "" \
    "merlin-xmldsig-twenty-three/signature" \
    "base64 xpath xslt enveloped-signature c14n-with-comments sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format $topfolder/merlin-xmldsig-twenty-three/certs/merlin.$cert_format --verification-gmt-time 2005-01-01+10:00:00 $url_map_xml_stylesheet_2005 $url_map_xml_stylesheet_b64_2005" \
    "--lax-key-search $priv_key_option:mykey $topfolder/keys/dsakey.$priv_key_format --pwd secret123 $url_map_xml_stylesheet_2005 $url_map_xml_stylesheet_b64_2005" \
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
    "--lax-key-search $priv_key_option $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret --verification-gmt-time 2005-01-01+10:00:00 $url_map_xml_stylesheet_2005"

# Advanced RSA OAEP modes:
# - MSCrypto only supports SHA1 for digest and mgf1
# - GCrypt/GnuTLS and MSCng only supoprts the *same* algorithm for *both* digest and mgf1
if [ "z$crypto" != "zmscrypto" -a "z$crypto" != "zmscng" -a "z$crypto" != "zgcrypt" ] ; then
    execDSigTest $res_success \
        "" \
        "merlin-xmlenc-five/encsig-hmac-sha256-rsa-oaep-mgf1p" \
        "sha1 hmac-sha256 rsa-oaep-mgf1p sha1  sha1" \
        "hmac rsa" \
        "--lax-key-search $priv_key_option $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret $url_map_xml_stylesheet_2005"
fi


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
    "--enabled-key-data key-value,key-name,dsa" \
    "--enabled-key-data key-value,key-name,dsa $priv_key_option:mykey $topfolder/keys/dsakey.$priv_key_format --pwd secret123" \
    "--enabled-key-data key-value,key-name,dsa"


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
    "--enabled-key-data key-value,dsa"

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
    "--enabled-key-data key-value,dsa"

execDSigTest $res_success \
    "" \
    "merlin-xpath-filter2-three/sign-spec" \
    "enveloped-signature xpath2 sha1 dsa-sha1" \
    "dsa" \
    "--enabled-key-data key-value,dsa"
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
    "--lax-key-search --pubkey-cert-$cert_format certs/rsa-cert.$cert_format $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-dsa-detached" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format certs/dsa-ca-cert.$cert_format --verification-gmt-time 2009-01-01+10:00:00 $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-dsa-enveloped" \
    "enveloped-signature sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format certs/dsa-ca-cert.$cert_format --verification-gmt-time 2009-01-01+10:00:00"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-dsa-enveloping" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--trusted-$cert_format certs/dsa-ca-cert.$cert_format --verification-gmt-time 2009-01-01+10:00:00"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-dsa-manifest" \
    "sha1 dsa-sha1" \
    "dsa x509" \
    "--enabled-key-data key-value,dsa,x509 --trusted-$cert_format certs/dsa-ca-cert.$cert_format --verification-gmt-time 2009-01-01+10:00:00 $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-hmac-md5-c14n-enveloping" \
    "md5 hmac-md5" \
    "hmac" \
    "--lax-key-search --hmackey certs/hmackey.bin"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-hmac-sha1-40-c14n-comments-detached" \
    "c14n-with-comments sha1 hmac-sha1" \
    "hmac" \
    "--lax-key-search --hmackey certs/hmackey.bin  $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-hmac-sha1-40-exclusive-c14n-comments-detached" \
    "exc-c14n-with-comments sha1 hmac-sha1" \
    "hmac" \
    "--lax-key-search --hmackey certs/hmackey.bin $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-hmac-sha1-exclusive-c14n-comments-detached" \
    "exc-c14n-with-comments sha1 hmac-sha1" \
    "hmac" \
    "--lax-key-search --hmackey certs/hmackey.bin  $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-hmac-sha1-exclusive-c14n-enveloped" \
    "enveloped-signature exc-c14n sha1 hmac-sha1" \
    "hmac" \
    "--lax-key-search --hmackey certs/hmackey.bin"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-detached" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --verification-gmt-time 2009-01-01+10:00:00  $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-detached-b64-transform" \
    "base64 sha1 rsa-sha1" \
    "rsa x509" \
    "--enabled-key-data key-value,rsa,x509  --trusted-$cert_format certs/rsa-ca-cert.$cert_format --verification-gmt-time 2009-01-01+10:00:00  $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-detached-xpath-transform" \
    "xpath sha1 rsa-sha1" \
    "rsa x509" \
    "--enabled-key-data key-value,rsa,x509 --trusted-$cert_format certs/rsa-ca-cert.$cert_format --verification-gmt-time 2009-01-01+10:00:00  $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-detached-xslt-transform-retrieval-method" \
    "xslt sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --verification-gmt-time 2009-01-01+10:00:00  $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-detached-xslt-transform" \
    "xslt sha1 rsa-sha1" \
    "rsa x509" \
    "--enabled-key-data key-value,rsa,x509 --trusted-$cert_format certs/rsa-ca-cert.$cert_format --verification-gmt-time 2009-01-01+10:00:00  $url_map_rfc3161"


execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-enveloped" \
    "enveloped-signature sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --verification-gmt-time 2009-01-01+10:00:00"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-enveloping" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --verification-gmt-time 2009-01-01+10:00:00"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-manifest-x509-data-cert-chain" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --verification-gmt-time 2009-01-01+10:00:00 $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-manifest-x509-data-cert" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --verification-gmt-time 2009-01-01+10:00:00 $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-manifest-x509-data-issuer-serial" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --untrusted-$cert_format certs/rsa-cert.$cert_format --verification-gmt-time 2009-01-01+10:00:00 $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-manifest-x509-data-ski" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --untrusted-$cert_format certs/rsa-cert.$cert_format --verification-gmt-time 2009-01-01+10:00:00 $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-manifest-x509-data-subject-name" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format --untrusted-$cert_format certs/rsa-cert.$cert_format --verification-gmt-time 2009-01-01+10:00:00 $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-manifest" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--enabled-key-data key-value,rsa,x509 --trusted-$cert_format certs/rsa-ca-cert.$cert_format --verification-gmt-time 2009-01-01+10:00:00 $url_map_rfc3161"

execDSigTest $res_success \
    "phaos-xmldsig-three" \
    "signature-rsa-xpath-transform-enveloped" \
    "enveloped-signature xpath sha1 rsa-sha1" \
    "rsa x509" \
    "--enabled-key-data key-value,rsa,x509 --trusted-$cert_format certs/rsa-ca-cert.$cert_format --verification-gmt-time 2009-01-01+10:00:00"


extra_message="Negative test: bad retrieval method"
execDSigTest $res_fail \
    "phaos-xmldsig-three" \
    "signature-rsa-detached-xslt-transform-bad-retrieval-method" \
    "xslt sha1 rsa-sha1" \
    "rsa x509" \
    "--enabled-key-data key-value,rsa,x509 --trusted-$cert_format certs/rsa-ca-cert.$cert_format $url_map_rfc3161"

extra_message="Negative test: bad digest"
execDSigTest $res_fail \
    "phaos-xmldsig-three" \
    "signature-rsa-enveloped-bad-digest-val" \
    "enveloped-signature sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

extra_message="Negative test: bad sig"
execDSigTest $res_fail \
    "phaos-xmldsig-three" \
    "signature-rsa-enveloped-bad-sig" \
    "enveloped-signature sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

extra_message="Negative test: CRL present"
execDSigTest $res_fail \
    "phaos-xmldsig-three" \
    "signature-rsa-manifest-x509-data-crl" \
    "sha1 rsa-sha1" \
    "rsa x509" \
    "--trusted-$cert_format certs/rsa-ca-cert.$cert_format"

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
    "aleksey-xmldsig-01/enveloped-gost2001" \
    "enveloped-signature gostr34102001-gostr3411" \
    "gost2001 x509" \
    "--trusted-$cert_format $topfolder/keys/gost2001ca.$cert_format --untrusted-$cert_format $topfolder/keys/ca2cert.$cert_format  --enabled-key-data x509 --verification-gmt-time 2007-01-01+10:00:00" \
    "$priv_key_option $topfolder/keys/gost2001key$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-gost2012-256" \
    "enveloped-signature gostr34112012-256 gostr34102012-gostr34112012-256" \
    "gostr34102012-256 x509" \
    "--insecure --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/gost2012_256key$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"

execDSigTest $res_success \
    "" \
    "aleksey-xmldsig-01/enveloped-gost2012-512" \
    "enveloped-signature gostr34112012-512 gostr34102012-gostr34112012-512" \
    "gostr34102012-512 x509" \
    "--insecure --enabled-key-data x509" \
    "$priv_key_option $topfolder/keys/gost2012_512key$priv_key_suffix.$priv_key_format --pwd secret123" \
    "--trusted-$cert_format $topfolder/keys/cacert.$cert_format --enabled-key-data x509"


##########################################################################
##########################################################################
##########################################################################
echo "--- testDSig finished" >> $logfile
echo "--- testDSig finished"
if [ -z "$XMLSEC_TEST_REPRODUCIBLE" ]; then
    echo "--- detailed log is written to  $logfile"
fi
