#!/bin/sh -x

OS_ARCH=`uname -o 2>/dev/null || echo ""`
OS_KERNEL=`uname -s`

#
# Get command line params
#
testfile="$1"
crypto="$2"
topfolder="$3"
xmlsec_app="$4"
file_format="$5"
timestamp=`date +%Y%m%d_%H%M%S`
exit_code=0

if test "z$OS_ARCH" = "zCygwin" || test "z$OS_ARCH" = "zMsys" ; then
    topfolder=`cygpath -wa "$topfolder"`
    xmlsec_app=`cygpath -a "$xmlsec_app"`
fi

# Ensure we get detailed errors
xmlsec_params="--verbose --print-crypto-library-errors"

#
# Prepare folders
#
if [ "z$TMPFOLDER" = "z" ] ; then
    TMPFOLDER=/tmp
fi
testname=`basename $testfile`
testfolder=$TMPFOLDER/xmlsec-$testname-$crypto-$timestamp
mkdir -p $testfolder

if test "z$OS_ARCH" = "zCygwin" || test "z$OS_ARCH" = "zMsys" ; then
    tmpfile=`cygpath -wa $testfolder/tmp.tmp`
    logfile=`cygpath -wa $testfolder/full.log`
    curlogfile=`cygpath -wa $testfolder/cur.log`
    failedlogfile=`cygpath -wa $testfolder/failed.log`
else
    tmpfile=$testfolder/tmp.tmp
    logfile=$testfolder/full.log
    curlogfile=$testfolder/cur.log
    failedlogfile=$testfolder/failed.log
fi

#
# Valgrind
#
if [ "z$crypto" = "zopenssl" ] ; then
    valgrind_suppression="--suppressions=$topfolder/valgrind-openssl.supp"
elif [ "z$crypto" = "znss" ] ; then
    valgrind_suppression="--suppressions=$topfolder/valgrind-nss.supp"
elif [ "z$crypto" = "zgcrypt" ] ; then
    valgrind_suppression="--suppressions=$topfolder/valgrind-gcrypt.supp"
elif [ "z$crypto" = "zgnutls" ] ; then
    valgrind_suppression="--suppressions=$topfolder/valgrind-gcrypt.supp"
else
    valgrind_suppression=""
fi

valgrind_options="--leak-check=full --show-reachable=yes --num-callers=32 --track-origins=yes -s"
if [ -n "$DEBUG_MEMORY" ] ; then
    export VALGRIND="valgrind $valgrind_options $valgrind_suppression"
    export REPEAT=3
    xmlsec_params="$xmlsec_params --repeat $REPEAT"
fi


#
# Setup crypto engine
#
if [ "z$XMLSEC_DEFAULT_CRYPTO" != "z" ] ; then
    xmlsec_params="$xmlsec_params --crypto $XMLSEC_DEFAULT_CRYPTO"
elif [ "z$crypto" != "z" ] ; then
    xmlsec_params="$xmlsec_params --crypto $crypto"
fi

#
# Setup extra vars
#
extra_vars=
if [ "z$crypto" = "zopenssl" -a "z$XMLSEC_OPENSSL_TEST_CONFIG" != "z" ] ; then
    if test "z$OS_ARCH" = "zCygwin" || test "z$OS_ARCH" = "zMsys" ; then
        opensslconf=`cygpath -wa $topfolder/$XMLSEC_OPENSSL_TEST_CONFIG`
    else
        opensslconf=$topfolder/$XMLSEC_OPENSSL_TEST_CONFIG
    fi
    extra_vars="$extra_vars OPENSSL_CONF=$opensslconf"
    export OPENSSL_CONF="$opensslconf"
fi

#
#  Configure supported features
#
case $XMLSEC_OPENSSL_VERSION in
*LibreSSL*)
    xmlsec_openssl_flavor="libressl"
    ;;
*BoringSSL*)
    xmlsec_openssl_flavor="boringssl"
    ;;
*AWSLC*)
    xmlsec_openssl_flavor="aws-lc"
    ;;
*)
    xmlsec_openssl_flavor="openssl"
    ;;
esac

# only original openssl supports --privkey-openssl-store
if [ "z$crypto" = "zopenssl" -a "z$xmlsec_openssl_flavor" = "zopenssl" ] ; then
    xmlsec_feature_openssl_store="yes"
else
    xmlsec_feature_openssl_store="no"
fi

# phaos certs use RSA-MD5 which might be disabled
if [ "z$crypto" = "zopenssl" -a "z$xmlsec_openssl_flavor" != "zaws-lc" -a "z$xmlsec_openssl_flavor" != "zboringssl" ] ; then
    extra_vars="$extra_vars OPENSSL_ENABLE_MD5_VERIFY=1"
    export OPENSSL_ENABLE_MD5_VERIFY=1

    xmlsec_feature_md5_certs="yes"
else
    xmlsec_feature_md5_certs="no"
fi


# Only OpenSSL / NSS / GnuTLS currently has capability to lookup the certs/keys using X509 data
if [ "z$crypto" = "zopenssl" -o "z$crypto" = "znss" -o "z$crypto" = "zgnutls" ] ; then
    xmlsec_feature_x509_data_lookup="yes"
else
    xmlsec_feature_x509_data_lookup="no"
fi

# Only NSS can lookup certs in NSS DB, skip certs verification for signatures
if [ "z$crypto" = "znss"  ] ; then
    xmlsec_feature_nssdb_lookup="yes"
else
    xmlsec_feature_nssdb_lookup="no"
fi

# MSCng only supports SHA1 as cert digests and cannot lookup the key
if [ "z$crypto" = "zmscng" ] ; then
    xmlsec_feature_x509_data_lookup_digest="yes"
else
    xmlsec_feature_x509_data_lookup_digest="no"
fi

# currently only openssl and gnutls support skipping time checks
# https://github.com/lsh123/xmlsec/issues/852
if [ "z$crypto" = "zopenssl" -o "z$crypto" = "zgnutls" -o "z$crypto" = "zmscng"  ] ; then
    xmlsec_feature_cert_check_skip_time="yes"
else
    xmlsec_feature_cert_check_skip_time="no"
fi

# currently only openssl/gnutls/nss/mscng support loading CRL from the command line
# https://github.com/lsh123/xmlsec/issues/583
if [ "z$crypto" = "zopenssl" -o  "z$crypto" = "zgnutls" -o "z$crypto" = "znss" -o "z$crypto" = "zmscng" ] ; then
    xmlsec_feature_crl_load="yes"
else
    xmlsec_feature_crl_load="no"
fi

# only openssl/gnutls/nss/mscng support crl verification
# https://github.com/lsh123/xmlsec/issues/585
if [ "z$crypto" = "zopenssl" -o  "z$crypto" = "zgnutls" -o "z$crypto" = "znss" -o "z$crypto" = "zmscng" ] ; then
    xmlsec_feature_crl_verification="yes"
else
    xmlsec_feature_crl_verification="no"
fi

# currently only openssl/mscng support CRL verification by time
# https://github.com/lsh123/xmlsec/issues/579
if [ "z$crypto" = "zopenssl" -o "z$crypto" = "zmscng" ] ; then
    xmlsec_feature_crl_check_skip_time="yes"
else
    xmlsec_feature_crl_check_skip_time="no"
fi

# only openssl, gnutls, nss, and mcng support key verification
# https://github.com/lsh123/xmlsec/issues/587
if [ "z$crypto" = "zopenssl" -o  "z$crypto" = "zgnutls" -o "z$crypto" = "znss" -o "z$crypto" = "zmscng" ] ; then
    xmlsec_feature_key_check="yes"
else
    xmlsec_feature_key_check="no"
fi


# Advanced RSA OAEP modes:
# - MSCrypto only supports SHA1 for digest and mgf1
if [ "z$crypto" != "zmscrypto" ] ; then
    xmlsec_feature_rsa_oaep_non_sha1="yes"
else
    xmlsec_feature_rsa_oaep_non_sha1="no"
fi

# Advanced RSA OAEP modes:
# - MSCrypto only supports SHA1 for digest and mgf1
# - GCrypt/GnuTLS and MSCng only supoprts the *same* algorithm for *both* digest and mgf1
if [ "z$crypto" != "zmscrypto" -a "z$crypto" != "zmscng" -a "z$crypto" != "zgcrypt" ] ; then
    xmlsec_feature_rsa_oaep_different_digest_and_mgf1="yes"
else
    xmlsec_feature_rsa_oaep_different_digest_and_mgf1="no"
fi

# Support for ASN1 signatures
if [ "z$crypto" = "zopenssl" -o  "z$crypto" = "zgnutls" -o "z$crypto" = "znss" -o  "z$crypto" = "zmscng"  ] ; then
    xmlsec_feature_asn1_signatures="yes"
else
    xmlsec_feature_asn1_signatures="no"
fi

# Support for context string in ML-DSA or SLH-DSA signatures
if [ "z$crypto" = "zopenssl" ] ; then
    xmlsec_feature_context_string="yes"
else
    xmlsec_feature_context_string="no"
fi

#
# Setup keys config
#
cert_format=$file_format

#
# MSCrypto needs persistent keys for pkcs12
#
pkcs12_key_extra_options=""
if [ "z$crypto" = "zmscrypto" ] ; then
    pkcs12_key_extra_options="--pkcs12-persist $pkcs12_key_extra_options"
fi

#
# GCrypt only supports DER format for now, others are good to go with PKCS12 for private keys
#
if [ "z$crypto" != "zgcrypt" ] ; then
    priv_key_option="$pkcs12_key_extra_options --pkcs12"
    priv_key_format="p12"
else
    priv_key_option="--privkey-der"
    priv_key_format="der"
fi

#
# NSS cannot import XDH (X25519/X448) private keys from OpenSSL-3.x-generated
# PKCS12 files (SEC_ERROR_PKCS12_UNABLE_TO_IMPORT_KEY).  MSCng cannot import
# them either because PFXImportCertStore does not support Curve25519/Curve448.
# Use unencrypted DER (PrivateKeyInfo) format for XDH keys in both cases.
#
if [ "z$crypto" = "znss" -o "z$crypto" = "zmscng" ] ; then
    xdh_priv_key_option="--privkey-der"
    xdh_priv_key_format="der"
else
    xdh_priv_key_option="$priv_key_option"
    xdh_priv_key_format="$priv_key_format"
fi

#
# NSS cannot import EdDSA (ED25519/ED448) private keys from OpenSSL-3.x-generated
# PKCS12 files (SEC_ERROR_PKCS12_UNABLE_TO_IMPORT_KEY).  Use unencrypted DER
# (PrivateKeyInfo) format for EdDSA keys when running under NSS.
#
if [ "z$crypto" = "znss" ] ; then
    eddsa_priv_key_option="--privkey-der"
    eddsa_priv_key_format="der"
else
    eddsa_priv_key_option="$priv_key_option"
    eddsa_priv_key_format="$priv_key_format"
fi

#
# GnuTLS cannot import EC keys from OpenSSL-3.x-generated xmlenc11-interop-2012
# PKCS12 files (PBES2/PBKDF2/AES-256-CBC encryption not supported).
# Use unencrypted DER (PrivateKeyInfo) format for those specific interop tests.
#
if [ "z$crypto" = "zgnutls" ] ; then
    ec_interop_priv_key_option="--privkey-der"
    ec_interop_priv_key_format="der"
else
    ec_interop_priv_key_option="$priv_key_option"
    ec_interop_priv_key_format="$priv_key_format"
fi

#
# Windows MSCng cannot load X9.42 DH keys from OpenSSL-generated PKCS12 files.
# Use unencrypted DER (PrivateKeyInfo/SubjectPublicKeyInfo) format instead.
#
if [ "z$crypto" = "zmscng" ] ; then
    dh_interop_priv_key_option="--privkey-der"
    dh_interop_priv_key_format="der"
else
    dh_interop_priv_key_option="$priv_key_option"
    dh_interop_priv_key_format="$priv_key_format"
fi

#
# Windows MSCng cannot load DHX private/public keys from PEM files.
# Use unencrypted DER (PrivateKeyInfo/SubjectPublicKeyInfo) format instead.
#
if [ "z$crypto" = "zmscng" ] ; then
    dhx_priv_key_option="--privkey-der"
    dhx_priv_key_format="der"
    dhx_pub_key_option="--pubkey-der"
    dhx_pub_key_format="der"
else
    dhx_priv_key_option="--privkey-pem"
    dhx_priv_key_format="pem"
    dhx_pub_key_option="--pubkey-pem"
    dhx_pub_key_format="pem"
fi

#
# GCrypt only supports DER format for now, others are good to go with certs for public keys
#
if [ "z$crypto" != "zgcrypt" ] ; then
    pub_key_option="--pubkey-cert-der"
    pub_key_format="crt"
else
    pub_key_option="--pubkey-der"
    pub_key_format="der"
fi
# GCrypt has problems reading public RSA keys and needs special handling
if [ "z$crypto" = "zgcrypt" ] ; then
    rsa_pub_key_suffix="-gcrypt"
else
    rsa_pub_key_suffix=""
fi

# On Windows, we needs to specify Crypto Service Provider (CSP)
# in the pkcs12 file to ensure it is loaded correctly to be used
# with SHA2 algorithms
if [ "z$crypto" = "zmscrypto" -o "z$crypto" = "zmscng" ] ; then
    priv_key_suffix="-win"
else
    priv_key_suffix=""
fi


#
# Misc
#
if [ -n "$PERF_TEST" ] ; then
    xmlsec_params="$xmlsec_params --repeat $PERF_TEST"
fi

if test "z$OS_ARCH" = "zCygwin" || test "z$OS_ARCH" = "zMsys" ; then
    diff_param=-uw
else
    diff_param=-u
fi


#
# Setup crypto config folder
#
config_number=0
setupCryptoConfig() {
    config_number=$((config_number + 1))
    if test "z$OS_ARCH" = "zCygwin" || test "z$OS_ARCH" = "zMsys" ; then
        crypto_config_folder=`cygpath -wa $testfolder/crypto-config-$config_number`
    else
        crypto_config_folder=$testfolder/crypto-config-$config_number
    fi
    mkdir $crypto_config_folder

    # see https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopensystemstorea
    if [ "z$crypto" = "zmscng" ] ; then
        default_crypto_config="MY"
    else
        default_crypto_config="$crypto_config_folder"
    fi
}

tearDownCryptoConfig() {
    if [ -n "$crypto_config_folder" ]; then
        rm -rf $crypto_config_folder
    fi
    unset crypto_config_folder
    unset default_crypto_config
}

setupTest() {
    # prepare
    old_pwd=`pwd`
    setupCryptoConfig
}

tearDownTest() {
    # cleanup
    tearDownCryptoConfig
    rm -f $tmpfile $tmpfile.2 $tmpfile.3
    if [ -n "$old_pwd" ]; then
        cd $old_pwd
    fi
    unset old_pwd
}

#
# Check the command result and print it to stdout
#
res_success="success"
res_fail="fail"
count_success=0
count_fail=0
count_skip=0
printRes() {
    expected_res="$1"
    actual_res="$2"

    # convert status to string
    if [ $actual_res -eq 0 ]; then
        actual_res_str=$res_success
    else
        actual_res_str=$res_fail
    fi

    # check
    if [ "z$expected_res" = "z$actual_res_str" ] ; then
        count_success=`expr $count_success + 1`
	    actual_res="0"
        echo "   OK"
    else
        count_fail=`expr $count_fail + 1`
	    actual_res="1"
        echo " Fail"
    fi

    # memlog
    if [ -f .memdump ] ; then
        cat .memdump >> $curlogfile
    fi

    return "$actual_res"
}

printCheckStatus() {
    check_res="$1"
    if [ $check_res -eq 0 ]; then
        echo "   OK"
    else
	count_skip=`expr $count_skip + 1`
        echo " Skip"
    fi
    return "$check_res"
}

extra_message=""

# prepare
rm -rf $tmpfile $tmpfile.2 $tmpfile.3

# run tests
source "$testfile"

# calculate success
percent_success=0
count_total=`expr $count_success + $count_fail + $count_skip`
if [ $count_total -gt 0 ] ; then
    percent_success=`expr 100 \* $count_success / $count_total`
fi

if [ "z$crypto" = "zopenssl" -a "z$xmlsec_openssl_flavor" = "zaws-lc" ] ; then
    # bunch of tests with MD5 certificates are disabled
    echo "--- OPENSSL FLAVOR: $xmlsec_openssl_flavor" >> $logfile
    echo "--- OPENSSL FLAVOR: $xmlsec_openssl_flavor"
    min_percent_success=75
elif [ "z$crypto" = "zopenssl" -a "z$xmlsec_openssl_flavor" = "zboringssl" ] ; then
    # bunch of tests with MD5 certificates are disabled
    echo "--- OPENSSL FLAVOR: $xmlsec_openssl_flavor" >> $logfile
    echo "--- OPENSSL FLAVOR: $xmlsec_openssl_flavor"
    min_percent_success=75
elif [ "z$crypto" = "zopenssl" ] ; then
    echo "--- OPENSSL FLAVOR: $xmlsec_openssl_flavor" >> $logfile
    echo "--- OPENSSL FLAVOR: $xmlsec_openssl_flavor"
    min_percent_success=90
elif [ "z$crypto" = "znss" ] ; then
    min_percent_success=75
elif [ "z$crypto" = "zgnutls" ] ; then
    min_percent_success=75
elif [ "z$crypto" = "zmscng" ] ; then
    min_percent_success=75
elif [ "z$crypto" = "zmscrypto" ] ; then
    min_percent_success=30
elif [ "z$crypto" = "zgcrypt" ] ; then
    min_percent_success=30
else
    min_percent_success=50
fi


# print results
echo "--- TOTAL OK: $count_success; OK (percent): $percent_success; TOTAL FAILED: $count_fail; TOTAL SKIPPED: $count_skip" >> $logfile
echo "--- TOTAL OK: $count_success; OK (percent): $percent_success; TOTAL FAILED: $count_fail; TOTAL SKIPPED: $count_skip"

# disable this check for test jeys since the number of tests is very small and the success percent is not representative
if [[ "$testfile" =~ 'testKeys' ]]; then
    XMLSEC_TEST_IGNORE_PERCENT_SUCCESS=1
    echo "--- SUCCESS PERCENT check is disabled for testKeys tests since the number of tests is very small and the success percent is not representative" >> $logfile
    echo "--- SUCCESS PERCENT check is disabled for testKeys tests since the number of tests is very small and the success percent is not representative"
fi

# print log file if failed (we have to have at least some good tests)
if [ $count_fail -ne 0 ] ; then
    cat $failedlogfile
    exit_code=$count_fail
elif [ $count_success -eq 0 ] ; then
    cat $logfile
    exit_code=1
elif [ -z "$XMLSEC_TEST_IGNORE_PERCENT_SUCCESS" -a $min_percent_success -gt $percent_success ]; then
    echo "--- SUCCESS PERCENT $percent_success IS LOWER THAN THE EXPECTED $min_percent_success PERCENT, FAILING TESTS"  >> $logfile
    echo "--- If you disabled some features and expect lower success percent then set environment variable 'XMLSEC_TEST_IGNORE_PERCENT_SUCCESS' before running the test" >> $logfile

    echo "--- SUCCESS PERCENT $percent_success IS LOWER THAN THE EXPECTED $min_percent_success PERCENT, FAILING TESTS"
    echo "--- If you disabled some features and expect lower success percent then set environment variable 'XMLSEC_TEST_IGNORE_PERCENT_SUCCESS' before running the test"

    cat $logfile
    exit_code=1
fi

# cleanup
rm -rf $tmpfile $tmpfile.2 tmpfile.3 $curlogfile

exit $exit_code
