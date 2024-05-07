#!/bin/sh
#
# This script needs to be called from testrun.sh script
#


# ensure this script is called from testrun.sh
if [ -z "$xmlsec_app" -o -z "$crypto_config_folder" ]; then
    echo "This script needs to be called from testrun.sh script"
    exit 1
fi

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
# xmlenc11-interop-2012:
# https://www.w3.org/TR/2012/NOTE-xmlenc-core1-interop-20121113/
#
##########################################################################

# AES GCM
execEncTest $res_success \
    "" \
    "xmlenc11-interop-2012/xenc11-example-AES128-GCM" \
    "aes128-gcm" \
    "" \
    "--lax-key-search --aeskey $topfolder/xmlenc11-interop-2012/xenc11-example-AES128-GCM.key" \
    "--aeskey:mykey $topfolder/xmlenc11-interop-2012/xenc11-example-AES128-GCM.key --binary-data $topfolder/xmlenc11-interop-2012/xenc11-example-AES128-GCM.data" \
    "--aeskey:mykey $topfolder/xmlenc11-interop-2012/xenc11-example-AES128-GCM.key"


# Advanced RSA OAEP modes:
# - MSCrypto only supports SHA1 for digest and mgf1
# - GCrypt/GnuTLS and MSCng only supoprts the *same* algorithm for *both* digest and mgf1
if [ "z$crypto" != "zmscrypto" -a "z$crypto" != "zmscng" -a "z$crypto" != "zgcrypt" ] ; then
    execEncTest $res_success \
        "" \
        "xmlenc11-interop-2012/cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p" \
        "aes128-gcm rsa-oaep-mgf1p sha256 sha1" \
        "" \
        "$priv_key_option:TestRsa2048Key $topfolder/xmlenc11-interop-2012/RSA-2048_SHA256WithRSA.$priv_key_format --pwd passwd" \
        "$priv_key_option:TestRsa2048Key $topfolder/xmlenc11-interop-2012/RSA-2048_SHA256WithRSA.$priv_key_format --pwd passwd --session-key aes-128 --xml-data $topfolder/xmlenc11-interop-2012/cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p.data"  \
        "$priv_key_option:TestRsa2048Key $topfolder/xmlenc11-interop-2012/RSA-2048_SHA256WithRSA.$priv_key_format --pwd passwd"

    execEncTest $res_success \
        "" \
        "xmlenc11-interop-2012/cipherText__RSA-3072__aes192-gcm__rsa-oaep-mgf1p__Sha256" \
        "aes192-gcm rsa-oaep-mgf1p sha256 sha1" \
        "" \
        "$priv_key_option:TestRsa3072Key $topfolder/xmlenc11-interop-2012/RSA-3072_SHA256WithRSA.$priv_key_format --pwd passwd" \
        "$priv_key_option:TestRsa3072Key $topfolder/xmlenc11-interop-2012/RSA-3072_SHA256WithRSA.$priv_key_format --pwd passwd --session-key aes-192 --xml-data $topfolder/xmlenc11-interop-2012/cipherText__RSA-3072__aes192-gcm__rsa-oaep-mgf1p__Sha256.data"  \
        "$priv_key_option:TestRsa3072Key $topfolder/xmlenc11-interop-2012/RSA-3072_SHA256WithRSA.$priv_key_format --pwd passwd"

    execEncTest $res_success \
        "" \
        "xmlenc11-interop-2012/cipherText__RSA-3072__aes256-gcm__rsa-oaep__Sha384-MGF_Sha1" \
        "aes256-gcm rsa-oaep-mgf1p sha384 sha1" \
        "" \
        "$priv_key_option:TestRsa3072Key $topfolder/xmlenc11-interop-2012/RSA-3072_SHA256WithRSA.$priv_key_format --pwd passwd" \
        "$priv_key_option:TestRsa3072Key $topfolder/xmlenc11-interop-2012/RSA-3072_SHA256WithRSA.$priv_key_format --pwd passwd --session-key aes-256 --xml-data $topfolder/xmlenc11-interop-2012/cipherText__RSA-3072__aes256-gcm__rsa-oaep__Sha384-MGF_Sha1.data"  \
        "$priv_key_option:TestRsa3072Key $topfolder/xmlenc11-interop-2012/RSA-3072_SHA256WithRSA.$priv_key_format --pwd passwd"

    execEncTest $res_success \
        "" \
        "xmlenc11-interop-2012/cipherText__RSA-4096__aes256-gcm__rsa-oaep__Sha512-MGF_Sha1_PSource" \
        "aes256-gcm rsa-oaep-mgf1p sha512 sha1" \
        "" \
        "$priv_key_option:TestRsa3072Key $topfolder/xmlenc11-interop-2012/RSA-4096_SHA256WithRSA.$priv_key_format --pwd passwd" \
        "$priv_key_option:TestRsa3072Key $topfolder/xmlenc11-interop-2012/RSA-4096_SHA256WithRSA.$priv_key_format --pwd passwd --session-key aes-256 --xml-data $topfolder/xmlenc11-interop-2012/cipherText__RSA-4096__aes256-gcm__rsa-oaep__Sha512-MGF_Sha1_PSource.data"  \
        "$priv_key_option:TestRsa3072Key $topfolder/xmlenc11-interop-2012/RSA-4096_SHA256WithRSA.$priv_key_format --pwd passwd"
fi

# ConcatCDF
execEncTest $res_success \
    "" \
    "xmlenc11-interop-2012/dkey-example-ConcatKDF-crypto" \
    "aes256-cbc concatkdf sha256" \
    "derived-key" \
    "--concatkdf-key:Secret1 $topfolder/xmlenc11-interop-2012/dkey-concatkdf.bin" \
    "--concatkdf-key:dkey $topfolder/xmlenc11-interop-2012/dkey-concatkdf.bin --binary $topfolder/xmlenc11-interop-2012/dkey-example-ConcatKDF-crypto.data" \
    "--concatkdf-key:dkey $topfolder/xmlenc11-interop-2012/dkey-concatkdf.bin"

execEncTest $res_success \
    "" \
    "xmlenc11-interop-2012/dkey3-example-ConcatKDF-crypto" \
    "aes256-cbc concatkdf sha256" \
    "derived-key" \
    "--concatkdf-key $topfolder/xmlenc11-interop-2012/dkey3-concatkdf.bin" \
    "--concatkdf-key:dkey3 $topfolder/xmlenc11-interop-2012/dkey3-concatkdf.bin --binary $topfolder/xmlenc11-interop-2012/dkey3-example-ConcatKDF-crypto.data" \
    "--concatkdf-key:dkey3 $topfolder/xmlenc11-interop-2012/dkey3-concatkdf.bin"

# PBKDF2
execEncTest $res_success \
    "" \
    "xmlenc11-interop-2012/dkey-example-PBKDF2-crypto" \
    "aes256-cbc pbkdf2 sha256" \
    "derived-key" \
    "--pbkdf2-key:dkey-pbkdf2 $topfolder/xmlenc11-interop-2012/dkey-pbkdf2.bin" \
    "--pbkdf2-key:dkey-pbkdf2 $topfolder/xmlenc11-interop-2012/dkey-pbkdf2.bin --binary $topfolder/xmlenc11-interop-2012/dkey-example-PBKDF2-crypto.data" \
    "--pbkdf2-key:dkey-pbkdf2 $topfolder/xmlenc11-interop-2012/dkey-pbkdf2.bin"

execEncTest $res_success \
    "" \
    "xmlenc11-interop-2012/dkey3-example-PBKDF2-crypto" \
    "aes256-cbc pbkdf2 sha256" \
    "derived-key" \
    "--pbkdf2-key:dkey3-pbkdf2 $topfolder/xmlenc11-interop-2012/dkey3-pbkdf2.bin" \
    "--pbkdf2-key:dkey3-pbkdf2 $topfolder/xmlenc11-interop-2012/dkey3-pbkdf2.bin --binary $topfolder/xmlenc11-interop-2012/dkey3-example-PBKDF2-crypto.data" \
    "--pbkdf2-key:dkey3-pbkdf2 $topfolder/xmlenc11-interop-2012/dkey3-pbkdf2.bin"


# ECDH-ES
execEncTest $res_success \
    "" \
    "xmlenc11-interop-2012/cipherText__EC-P256__aes128-gcm__kw-aes128__ECDH-ES__ConcatKDF" \
    "aes128-gcm kw-aes128 concatkdf ecdh-es sha256" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,ec $priv_key_option:EC-P256 $topfolder/xmlenc11-interop-2012/EC-P256_SHA256WithECDSA-orig.$priv_key_format --pwd passwd" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,ec --session-key aes-128 $priv_key_option:EC-P256 $topfolder/xmlenc11-interop-2012/EC-P256_SHA256WithECDSA.$priv_key_format $pub_key_option:ecdsa-secp256r1 $topfolder/keys/ecdsa-secp256r1-cert.$pub_key_format --pwd secret123 --xml-data $topfolder/xmlenc11-interop-2012/cipherText__EC-P256__aes128-gcm__kw-aes128__ECDH-ES__ConcatKDF.data" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,ec $priv_key_option:ecdsa-secp256r1 $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format  --pwd secret123"

execEncTest $res_success \
    "" \
    "xmlenc11-interop-2012/cipherText__EC-P384__aes192-gcm__kw-aes192__ECDH-ES__ConcatKDF" \
    "aes192-gcm kw-aes192 concatkdf ecdh-es sha256" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,ec  $priv_key_option:EC-P384 $topfolder/xmlenc11-interop-2012/EC-P384_SHA256WithECDSA-orig.$priv_key_format --pwd passwd" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,ec --session-key aes-192 $priv_key_option:EC-P384 $topfolder/xmlenc11-interop-2012/EC-P384_SHA256WithECDSA.$priv_key_format $pub_key_option:ecdsa-secp384r1 $topfolder/keys/ecdsa-secp384r1-cert.$pub_key_format --pwd secret123 --xml-data $topfolder/xmlenc11-interop-2012/cipherText__EC-P384__aes192-gcm__kw-aes192__ECDH-ES__ConcatKDF.data" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,ec $priv_key_option:ecdsa-secp384r1 $topfolder/keys/ecdsa-secp384r1-key.$priv_key_format  --pwd secret123"

execEncTest $res_success \
    "" \
    "xmlenc11-interop-2012/cipherText__EC-P521__aes256-gcm__kw-aes256__ECDH-ES__ConcatKDF" \
    "aes256-gcm kw-aes256 concatkdf ecdh-es sha256" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,ec $priv_key_option:EC-P521 $topfolder/xmlenc11-interop-2012/EC-P521_SHA256WithECDSA-orig.$priv_key_format --pwd passwd" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,ec --session-key aes-256 $priv_key_option:EC-P521 $topfolder/xmlenc11-interop-2012/EC-P521_SHA256WithECDSA.$priv_key_format $pub_key_option:ecdsa-secp521r1 $topfolder/keys/ecdsa-secp521r1-cert.$pub_key_format --pwd secret123 --xml-data $topfolder/xmlenc11-interop-2012/cipherText__EC-P521__aes256-gcm__kw-aes256__ECDH-ES__ConcatKDF.data" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,ec $priv_key_option:ecdsa-secp521r1 $topfolder/keys/ecdsa-secp521r1-key.$priv_key_format  --pwd secret123"

# DH-ES
execEncTest $res_success \
    "" \
    "xmlenc11-interop-2012/cipherText__DH-1024__aes128-gcm__kw-aes128__dh-es__ConcatKDF" \
    "aes128-gcm kw-aes128 concatkdf dh-es sha256" \
    "agreement-method enc-key dh" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,dh $priv_key_option:DH-1024 $topfolder/xmlenc11-interop-2012/DH-1024_SHA256WithDSA.$priv_key_format --pwd passwd" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,dh --session-key aes-128 --privkey-pem:dh1024-first $topfolder/keys/dh1024-first-key.pem --pubkey-pem:dh1024-second $topfolder/keys/dh1024-second-pubkey.pem --xml-data $topfolder/xmlenc11-interop-2012/cipherText__DH-1024__aes128-gcm__kw-aes128__dh-es__ConcatKDF.data" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,dh --privkey-pem:dh1024-second $topfolder/keys/dh1024-second-key.pem"



##########################################################################
#
# aleksey-xmlenc-01
#
#########################################################################

# ECDH + ConcatKDF + SHA1
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha1_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es concatkdf sha1" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha1_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123"

# ECDH + ConcatKDF + SHA2
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha224_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es concatkdf sha224" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha224_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha256_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es concatkdf sha256" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha256_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha384_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es concatkdf sha384" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha384_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha512_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es concatkdf sha512" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha512_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123"

# ECDH + ConcatKDF + SHA3
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha3_224_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es concatkdf sha3-224" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha3_224_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha3_256_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es concatkdf sha3-256" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha3_256_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha3_384_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es concatkdf sha3-384" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha3_384_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha3_512_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es concatkdf sha3-512" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha3_512_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123"

# ECDH + PBKDF2+SHA1
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha1_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es pbkdf2 hmac-sha1" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha1_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123"

# ECDH + PBKDF2+SHA2
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha224_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es pbkdf2 hmac-sha224" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha224_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha256_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es pbkdf2 hmac-sha256" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha256_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha384_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es pbkdf2 hmac-sha384" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha384_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha512_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es pbkdf2 hmac-sha512" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ecdsa-secp256r1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha512_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ecdsa-secp256r1-second-key.$priv_key_format --pwd secret123"

# Only OpenSSL / NSS / GnuTLS currently has capability to lookup the certs/keys using X509 data
# These tests verify keys lookup, certificates lookup is tested in XMLDSig.sh
if [ "z$crypto" = "zopenssl" -o "z$crypto" = "znss" -o "z$crypto" = "zgnutls" ] ; then
    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_subject_name" \
        "aes256-cbc rsa-1_5" \
        "x509" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/largersacert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_subject_name.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_issuer_name_serial" \
        "aes256-cbc rsa-1_5" \
        "x509" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/largersacert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_issuer_name_serial.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_ski" \
        "aes256-cbc rsa-1_5" \
        "x509" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/largersacert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_ski.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha1" \
        "aes256-cbc rsa-1_5 sha1" \
        "x509" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/largersacert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha1.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha224" \
        "aes256-cbc rsa-1_5 sha224" \
        "x509" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/largersacert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha224.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha256" \
        "aes256-cbc rsa-1_5 sha256" \
        "x509" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/largersacert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha256.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha384" \
        "aes256-cbc rsa-1_5 sha384" \
        "x509" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/largersacert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha384.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha512" \
        "aes256-cbc rsa-1_5 sha512" \
        "x509" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/largersacert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha512.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha3_224" \
        "aes256-cbc rsa-1_5 sha3-224" \
        "x509" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/largersacert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha3_224.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha3_256" \
        "aes256-cbc rsa-1_5 sha3-256" \
        "x509" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/largersacert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha3_256.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha3_384" \
        "aes256-cbc rsa-1_5 sha3-384" \
        "x509" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/largersacert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha3_384.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha3_512" \
        "aes256-cbc rsa-1_5 sha3-512" \
        "x509" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/largersacert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha3_512.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/largersakey.$priv_key_format --pwd secret123"
fi

# same file is encrypted with two keys, test both
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-two-enc-keys" \
    "aes256-cbc rsa-1_5" \
    "x509" \
    "$priv_key_option:key1 $topfolder/keys/cakey.$priv_key_format --pwd secret123" \
    "--session-key aes-256 --xml-data $topfolder/aleksey-xmlenc-01/enc-two-enc-keys.data --pubkey-cert-$cert_format:key1 $topfolder/keys/cacert.$cert_format --pubkey-cert-$cert_format:key2 $topfolder/keys/ca2cert.$cert_format" \
    "$priv_key_option:key1 $topfolder/keys/cakey.$priv_key_format --pwd secret123"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-two-enc-keys" \
    "aes256-cbc rsa-1_5" \
    "x509" \
    "$priv_key_option:key2 $topfolder/keys/ca2key.$priv_key_format --pwd secret123" \
    "--session-key aes-256 --xml-data $topfolder/aleksey-xmlenc-01/enc-two-enc-keys.data --pubkey-cert-$cert_format:key1 $topfolder/keys/cacert.$cert_format --pubkey-cert-$cert_format:key2 $topfolder/keys/ca2cert.$cert_format" \
    "$priv_key_option:key2 $topfolder/keys/ca2key.$priv_key_format --pwd secret123"


execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/large_input" \
    "aes256-cbc rsa-1_5" \
    "x509" \
    "$priv_key_option:my-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
    "--session-key aes-256 --xml-data $topfolder/aleksey-xmlenc-01/large_input.data --pubkey-cert-$cert_format:my-key $topfolder/keys/largersacert.$cert_format" \
    "$priv_key_option:my-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-element-isolatin1" \
    "aes256-cbc rsa-1_5" \
    "x509" \
    "$priv_key_option:my-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
    "--session-key aes-256 --xml-data $topfolder/aleksey-xmlenc-01/enc-element-isolatin1.data --pubkey-cert-$cert_format:my-key $topfolder/keys/largersacert.$cert_format" \
    "$priv_key_option:my-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-content-isolatin1" \
    "aes256-cbc rsa-1_5" \
    "x509" \
    "$priv_key_option:my-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
    "--session-key aes-256 --xml-data $topfolder/aleksey-xmlenc-01/enc-content-isolatin1.data --node-name http://example.org/paymentv2:CreditCard --pubkey-cert-$cert_format:my-key $topfolder/keys/largersacert.$cert_format" \
    "$priv_key_option:my-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-keyname" \
    "tripledes-cbc" \
    "" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $keysfile --binary-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-keyname.data" \
    "--keys-file $keysfile"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-keyname2" \
    "tripledes-cbc" \
    "" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $keysfile --binary-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-keyname2.data" \
    "--keys-file $keysfile"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes128cbc-keyname" \
    "aes128-cbc" \
    "" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $keysfile --binary-data $topfolder/aleksey-xmlenc-01/enc-aes128cbc-keyname.data" \
    "--keys-file $keysfile"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes192cbc-keyname" \
    "aes192-cbc" \
    "" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $keysfile --binary-data $topfolder/aleksey-xmlenc-01/enc-aes192cbc-keyname.data" \
    "--keys-file $keysfile"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes192cbc-keyname-ref" \
    "aes192-cbc" \
    "" \
    "--keys-file $topfolder/keys/keys.xml"


extra_message="Negative test: all cipher references are disabled"
execEncTest $res_fail \
    "" \
    "aleksey-xmlenc-01/enc-aes192cbc-keyname-ref" \
    "" \
    "" \
    "--keys-file $topfolder/keys/keys.xml --enabled-cipher-reference-uris empty"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes256cbc-keyname" \
    "aes256-cbc" \
    "" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $keysfile --binary-data $topfolder/aleksey-xmlenc-01/enc-aes256cbc-keyname.data" \
    "--keys-file $keysfile"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-keyname-content" \
    "tripledes-cbc" \
    " " \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $keysfile --xml-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-keyname-content.data --node-id Test" \
    "--keys-file $keysfile"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-keyname-element" \
    "tripledes-cbc" \
    " " \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $keysfile --xml-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-keyname-element.data --node-id Test" \
    "--keys-file $keysfile"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-keyname-element-root" \
    "tripledes-cbc" \
    " " \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $keysfile --xml-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-keyname-element-root.data --node-id Test" \
    "--keys-file $keysfile"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-aes192-keyname" \
    "tripledes-cbc kw-aes192" \
    "enc-key aes des" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $keysfile  --session-key des-192  --binary-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-aes192-keyname.data" \
    "--keys-file $keysfile"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1-params" \
    "aes256-cbc rsa-oaep-mgf1p sha1" \
    "" \
    "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
    "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1-params.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1" \
    "aes256-cbc rsa-oaep-mgf1p sha1 sha1" \
    " " \
    "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
    "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

# Advanced RSA OAEP modes:
# - MSCrypto only supports SHA1 for digest and mgf1
# - GCrypt/GnuTLS and MSCng only supoprts the *same* algorithm for *both* digest and mgf1
if [ "z$crypto" != "zmscrypto" -a "z$crypto" != "zmscng" -a "z$crypto" != "zgcrypt" ] ; then
    # various digest and default mgf1 (sha1)
    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_md5" \
        "aes256-cbc rsa-oaep-mgf1p md5 sha1" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_md5.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_ripemd160" \
        "aes256-cbc rsa-oaep-mgf1p ripemd160 sha1" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_ripemd160.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha224" \
        "aes256-cbc rsa-oaep-mgf1p sha224 sha1" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha224.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha256" \
        "aes256-cbc rsa-oaep-mgf1p sha256 sha1" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha256.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha384" \
        "aes256-cbc rsa-oaep-mgf1p sha384 sha1" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha384.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512" \
        "aes256-cbc rsa-oaep-mgf1p sha512 sha1" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    # various digest and mgf1=sha512
    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_md5_mgf1_sha512" \
        "aes256-cbc rsa-oaep-mgf1p md5 sha512" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_md5_mgf1_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_ripemd160_mgf1_sha512" \
        "aes256-cbc rsa-oaep-mgf1p ripemd160 sha512" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_ripemd160_mgf1_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1_mgf1_sha512" \
        "aes256-cbc rsa-oaep-mgf1p sha1 sha512" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1_mgf1_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha224_mgf1_sha512" \
        "aes256-cbc rsa-oaep-mgf1p sha224 sha512" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha224_mgf1_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha256_mgf1_sha512" \
        "aes256-cbc rsa-oaep-mgf1p sha256 sha512" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha256_mgf1_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha384_mgf1_sha512" \
        "aes256-cbc rsa-oaep-mgf1p sha384 sha512" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha384_mgf1_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    # digest=sha512 and various mgf1
    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha1" \
        "aes256-cbc rsa-oaep-mgf1p sha512 sha1" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha224" \
        "aes256-cbc rsa-oaep-mgf1p sha512 sha224" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha224.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha256" \
        "aes256-cbc rsa-oaep-mgf1p sha512 sha256" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha256.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha384" \
        "aes256-cbc rsa-oaep-mgf1p sha512 sha384" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha384.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"
fi

# Advanced RSA OAEP modes:
# - MSCrypto only supports SHA1 for digest and mgf1
if [ "z$crypto" != "zmscrypto" ] ; then
    # same diges for both digest and MGF1
    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1_mgf1_sha1" \
        "aes256-cbc rsa-oaep-mgf1p sha1 sha1" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1_mgf1_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha224_mgf1_sha224" \
        "aes256-cbc rsa-oaep-mgf1p sha224 sha224" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha224_mgf1_sha224.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha256_mgf1_sha256" \
        "aes256-cbc rsa-oaep-mgf1p sha256 sha256" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha256_mgf1_sha256.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha384_mgf1_sha384" \
        "aes256-cbc rsa-oaep-mgf1p sha384 sha384" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha384_mgf1_sha384.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha512" \
        "aes256-cbc rsa-oaep-mgf1p sha512 sha512" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"

    # RSA OAEP XMLEnc 1.1 transform (exactly same as 1.0 but different URL)
    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_enc11_sha512_mgf1_sha512" \
        "aes256-cbc rsa-oaep-enc11 sha512 sha512" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123 --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_enc11_sha512_mgf1_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/keys/largersakey.$priv_key_format --pwd secret123"
fi

# same test but decrypt using two different keys
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-two-recipients" \
    "tripledes-cbc rsa-1_5" \
    "x509" \
    "--lax-key-search $priv_key_option:pub1 $topfolder/keys/rsakey.$priv_key_format --pwd secret123" \
    "--pubkey-cert-$cert_format:pub1 $topfolder/keys/rsacert.$cert_format --pubkey-cert-$cert_format:pub2 $topfolder/keys/largersacert.$cert_format --session-key des-192 --xml-data $topfolder/aleksey-xmlenc-01/enc-two-recipients.data" \
    "--lax-key-search $priv_key_option:pub1 $topfolder/keys/rsakey.$priv_key_format --pwd secret123"
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-two-recipients" \
    "tripledes-cbc rsa-1_5" \
    "x509" \
    "--lax-key-search $priv_key_option:pub1 $topfolder/keys/largersakey.$priv_key_format --pwd secret123" \
    "--pubkey-cert-$cert_format:pub1 $topfolder/keys/rsacert.$cert_format --pubkey-cert-$cert_format:pub2 $topfolder/keys/largersacert.$cert_format --session-key des-192 --xml-data $topfolder/aleksey-xmlenc-01/enc-two-recipients.data" \
    "--lax-key-search $priv_key_option:pub1 $topfolder/keys/largersakey.$priv_key_format --pwd secret123"


##########################################################################
#
# merlin-xmlenc-five
#
##########################################################################

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-data-aes128-cbc" \
    "aes128-cbc" \
    "" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --binary-data $topfolder/merlin-xmlenc-five/encrypt-data-aes128-cbc.data" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-content-tripledes-cbc" \
    "tripledes-cbc" \
    "" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/merlin-xmlenc-five/encrypt-content-tripledes-cbc.data --node-id Payment" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-content-aes256-cbc-prop" \
    "aes256-cbc" \
    "" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/merlin-xmlenc-five/encrypt-content-aes256-cbc-prop.data --node-id Payment" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-element-aes192-cbc-ref" \
    "aes192-cbc" \
    "" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-element-aes128-cbc-rsa-1_5" \
    "aes128-cbc rsa-1_5" \
    "" \
    "--lax-key-search $priv_key_option $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret --verification-gmt-time 2003-01-01+10:00:00" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --session-key aes-128 $priv_key_option:mykey $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --xml-data $topfolder/merlin-xmlenc-five/encrypt-element-aes128-cbc-rsa-1_5.data --node-id Purchase --pwd secret"  \
    "$priv_key_option:mykey $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-data-tripledes-cbc-rsa-oaep-mgf1p" \
    "tripledes-cbc rsa-oaep-mgf1p sha1" \
    "" \
    "--lax-key-search $priv_key_option $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --session-key des-192 $priv_key_option:mykey $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --binary-data $topfolder/merlin-xmlenc-five/encrypt-data-tripledes-cbc-rsa-oaep-mgf1p.data --pwd secret"  \
    "$priv_key_option:mykey $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret"

# Advanced RSA OAEP modes:
# - MSCrypto only supports SHA1 for digest and mgf1
# - GCrypt/GnuTLS and MSCng only supoprts the *same* algorithm for *both* digest and mgf1
if [ "z$crypto" != "zmscrypto" -a "z$crypto" != "zmscng" -a "z$crypto" != "zgcrypt" ] ; then
    execEncTest $res_success \
        "" \
        "merlin-xmlenc-five/encrypt-data-tripledes-cbc-rsa-oaep-mgf1p-sha256" \
        "tripledes-cbc rsa-oaep-mgf1p sha256 sha1" \
        "" \
        "--lax-key-search $priv_key_option $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret" \
        "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --session-key des-192 $priv_key_option:mykey $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --binary-data $topfolder/merlin-xmlenc-five/encrypt-data-tripledes-cbc-rsa-oaep-mgf1p-sha256.data --pwd secret"  \
        "$priv_key_option:mykey $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret"
fi

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-data-aes256-cbc-kw-tripledes" \
    "aes256-cbc kw-tripledes" \
    "" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --session-key aes-256 --binary-data $topfolder/merlin-xmlenc-five/encrypt-data-aes256-cbc-kw-tripledes.data" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-content-aes128-cbc-kw-aes192" \
    "aes128-cbc kw-aes192" \
    "" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --session-key aes-128 --node-name urn:example:po:PaymentInfo --xml-data $topfolder/merlin-xmlenc-five/encrypt-content-aes128-cbc-kw-aes192.data" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-data-aes192-cbc-kw-aes256" \
    "aes192-cbc kw-aes256" \
    "" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --session-key aes-192 --binary-data $topfolder/merlin-xmlenc-five/encrypt-data-aes192-cbc-kw-aes256.data" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-element-tripledes-cbc-kw-aes128" \
    "tripledes-cbc kw-aes128" \
    "" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml  --session-key des-192 --node-name urn:example:po:PaymentInfo --xml-data $topfolder/merlin-xmlenc-five/encrypt-element-tripledes-cbc-kw-aes128.data" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml"

execEncTest $res_success \
    "" \
    "merlin-xmlenc-five/encrypt-element-aes256-cbc-retrieved-kw-aes256" \
    "aes256-cbc kw-aes256" \
    "" \
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml"


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
    "" \
    "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
    "--session-key des-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-3des-kt-rsa1_5.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-3des-kt-rsa_oaep_sha1" \
    "tripledes-cbc rsa-oaep-mgf1p sha1 sha1" \
    "" \
    "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
    "--session-key des-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-3des-kt-rsa_oaep_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"

# Advanced RSA OAEP modes:
# - MSCrypto only supports SHA1 for digest and mgf1
# - GCrypt/GnuTLS and MSCng only supoprts the *same* algorithm for *both* digest and mgf1
if [ "z$crypto" != "zmscrypto" -a "z$crypto" != "zmscng" -a "z$crypto" != "zgcrypt" ] ; then
    execEncTest $res_success \
        "" \
        "01-phaos-xmlenc-3/enc-element-3des-kt-rsa_oaep_sha256" \
        "tripledes-cbc rsa-oaep-mgf1p sha256 sha1" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
        "--session-key des-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-3des-kt-rsa_oaep_sha256.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"

    execEncTest $res_success \
        "" \
        "01-phaos-xmlenc-3/enc-element-3des-kt-rsa_oaep_sha512" \
        "tripledes-cbc rsa-oaep-mgf1p sha512 sha1" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
        "--session-key des-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-3des-kt-rsa_oaep_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"
fi

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-aes128-kt-rsa1_5" \
    "aes128-cbc rsa-1_5" \
    "" \
    "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
    "--session-key aes-128 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-aes128-kt-rsa1_5.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-aes128-kt-rsa_oaep_sha1" \
    "aes128-cbc rsa-oaep-mgf1p sha1 sha1" \
    "" \
    "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
    "--session-key aes-128 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-aes128-kt-rsa_oaep_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-aes192-kt-rsa_oaep_sha1" \
    "aes192-cbc rsa-oaep-mgf1p sha1 sha1" \
    "" \
    "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
    "--session-key aes-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-aes192-kt-rsa_oaep_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-text-aes192-kt-rsa1_5" \
    "aes192-cbc rsa-1_5" \
    "" \
    "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
    "--session-key aes-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-text-aes192-kt-rsa1_5.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-content-aes256-kt-rsa1_5" \
    "aes256-cbc rsa-1_5" \
    "" \
    "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
    "--session-key aes-256 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-content-aes256-kt-rsa1_5.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"


extra_message="Negative test: missing key"
execEncTest $res_fail \
    "" \
    "01-phaos-xmlenc-3/enc-content-aes256-kt-rsa1_5" \
    "" \
    "" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-retrieval-method-uris empty"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-text-aes256-kt-rsa_oaep_sha1" \
    "aes256-cbc rsa-oaep-mgf1p sha1  sha1" \
    "" \
    "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
    "--session-key aes-256 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-text-aes256-kt-rsa_oaep_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
    "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-3des-kw-3des" \
    "tripledes-cbc kw-tripledes" \
    "" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key des-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-3des-kw-3des.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-content-aes128-kw-3des" \
    "aes128-cbc kw-tripledes" \
    "" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key aes-128 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-content-aes128-kw-3des.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-aes128-kw-aes128" \
    "aes128-cbc kw-aes128" \
    "" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key aes-128 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-aes128-kw-aes128.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-aes128-kw-aes256" \
    "aes128-cbc kw-aes256" \
    "" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key aes-128 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-aes128-kw-aes256.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-content-3des-kw-aes192" \
    "tripledes-cbc kw-aes192" \
    "" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key des-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-content-3des-kw-aes192.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-content-aes192-kw-aes256" \
    "aes192-cbc kw-aes256" \
    "" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key aes-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-content-aes192-kw-aes256.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-aes192-kw-aes192" \
    "aes192-cbc kw-aes192" \
    "" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key aes-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-aes192-kw-aes192.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-element-aes256-kw-aes256" \
    "aes256-cbc kw-aes256" \
    "" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key aes-256 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-aes256-kw-aes256.data --node-name http://example.org/paymentv2:CreditCard" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-text-3des-kw-aes256" \
    "tripledes-cbc kw-aes256" \
    "" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key des-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-text-3des-kw-aes256.data --node-name http://example.org/paymentv2:CreditCard"  \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml"

execEncTest $res_success \
    "" \
    "01-phaos-xmlenc-3/enc-text-aes128-kw-aes192" \
    "aes128-cbc kw-aes192" \
    "" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml" \
    "--session-key aes-128 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-text-aes128-kw-aes192.data --node-name http://example.org/paymentv2:CreditCard"  \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml"

extra_message="Negative test: bad alg enc element"
execEncTest $res_fail \
    "" \
    "01-phaos-xmlenc-3/bad-alg-enc-element-aes128-kw-3des" \
    "" \
    "" \
    "--keys-file $topfolder/01-phaos-xmlenc-3/keys.xml"


#01-phaos-xmlenc-3/enc-element-3des-ka-dh.xml
#01-phaos-xmlenc-3/enc-element-aes128-ka-dh.xml
#01-phaos-xmlenc-3/enc-element-aes192-ka-dh.xml
#01-phaos-xmlenc-3/enc-element-aes256-ka-dh.xml


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
                    "" \
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
                    "" \
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
echo "--- testEnc finished" >> $logfile
echo "--- testEnc finished"
if [ -z "$XMLSEC_TEST_REPRODUCIBLE" ]; then
    echo "--- detailed log is written to  $logfile"
fi
