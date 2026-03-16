#!/bin/sh
#
# This script needs to be called from testrun.sh script
#

# ensure this script is called from testrun.sh
if [ -z "$xmlsec_app" -o -z "$xmlsec_params" ]; then
    echo "This script needs to be called from testrun.sh script"
    exit 1
fi

##########################################################################
##########################################################################
##########################################################################
if [ -z "$XMLSEC_TEST_REPRODUCIBLE" ]; then
    echo "--- testKeys started for xmlsec-$crypto library ($timestamp) ---"
fi
echo "--- LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
echo "--- LTDL_LIBRARY_PATH=$LTDL_LIBRARY_PATH"
if [ -z "$XMLSEC_TEST_REPRODUCIBLE" ]; then
    echo "--- log file is $logfile"
fi
echo "--- testKeys started for xmlsec-$crypto library ($timestamp) ---" >> $logfile
echo "--- LD_LIBRARY_PATH=$LD_LIBRARY_PATH" >> $logfile
echo "--- LTDL_LIBRARY_PATH=$LTDL_LIBRARY_PATH" >> $logfile


##########################################################################
##########################################################################
##########################################################################
#
# Keys test function
#
execKeysTest() {
    execKeysTestWithCryptoConfig "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" ""
}

execKeysTestWithCryptoConfig() {
    expected_res="$1"
    req_key_data="$2"
    key_name="$3"
    alg_name="$4"
    privkey_file="$5"
    pubkey_file="$6"
    certkey_file="$7"
    asym_key_test="$8"
    key_test_options="$9"
    crypto_config="${10}"
    failures=0

    if [ -n "$XMLSEC_TEST_NAME" -a "$XMLSEC_TEST_NAME" != "$key_name" ]; then
        return
    fi

    # prepare
    setupTest

    xmlsec_feature_pkcs12="yes"
    xmlsec_feature_pkcs12_persist="no"
    xmlsec_feature_pkcs12_keyname="yes"
    xmlsec_feature_pkcs8="yes"
    xmlsec_feature_privkey_pem="yes"
    xmlsec_feature_privkey_der="yes"
    xmlsec_feature_pubkey_pem="yes"
    xmlsec_feature_pubkey_der="yes"
    xmlsec_feature_cert_pem="yes"
    xmlsec_feature_cert_der="yes"
    xmlsec_feature_gen_key="yes"

    # NSS limitations
    if [ "z$crypto" = "znss" ] ; then
        xmlsec_feature_pkcs8="no"
        xmlsec_feature_privkey_pem="no"
        xmlsec_feature_privkey_der="no"
        xmlsec_feature_pubkey_pem="no"

        case "$alg_name" in
            eddsa-ed25519)
                xmlsec_feature_pkcs12="no"
                xmlsec_feature_pkcs12_keyname="no"
                ;;
            eddsa-ed448)
                xmlsec_feature_pkcs12="no"
                xmlsec_feature_pkcs12_keyname="no"
                xmlsec_feature_pubkey_der="no"
                xmlsec_feature_cert_pem="no"
                xmlsec_feature_cert_der="no"
                ;;
        esac
    fi

    # MSCNG limitations
    if [ "z$crypto" = "zmscng" ] ; then
        xmlsec_feature_pkcs12_persist="yes"
        xmlsec_feature_pkcs8="no"
        xmlsec_feature_privkey_pem="no"
        xmlsec_feature_privkey_der="no"
        xmlsec_feature_pubkey_pem="no"
        xmlsec_feature_pubkey_der="no"
        xmlsec_feature_cert_pem="no"
    fi

    # MSCRYPTO limitations
    if [ "z$crypto" = "zmscrypto" ] ; then
        xmlsec_feature_pkcs12_keyname="no"
        xmlsec_feature_pkcs8="no"
        xmlsec_feature_privkey_pem="no"
        xmlsec_feature_privkey_der="no"
        xmlsec_feature_pubkey_pem="no"
        xmlsec_feature_pubkey_der="no"
        xmlsec_feature_cert_pem="no"
    fi

    # Gcrypt limitations
    if [ "z$crypto" = "zgcrypt" ] ; then
        xmlsec_feature_pkcs12="no"
        xmlsec_feature_pkcs12_keyname="no"
        xmlsec_feature_pkcs8="no"
        xmlsec_feature_privkey_pem="no"
        xmlsec_feature_pubkey_pem="no"
        xmlsec_feature_cert_pem="no"
        xmlsec_feature_cert_der="no"
    fi

    # Keys file path
    if test "z$OS_ARCH" = "zCygwin" || test "z$OS_ARCH" = "zMsys" ; then
        keysfile=`cygpath -wa $crypto_config_folder/keys.xml`
    else
        keysfile=$crypto_config_folder/keys.xml
    fi

    # check params
    if [ "z$expected_res" != "z$res_success" -a "z$expected_res" != "z$res_fail" ] ; then
        echo " Bad parameter: expected_res=$expected_res"
        tearDownTest
        return
    fi
    if [ "z$crypto_config" = "z" ] ; then
        crypto_config="$default_crypto_config"
    fi

    # starting test
    echo "Test: $alg_name $extra_message"
    echo "Test: $alg_name $extra_message -- expected $expected_res" > $curlogfile
    extra_message=""

    # check key data
    if [ -n "$req_key_data" ] ; then
        printf "    Checking required key data                            "
        echo "$extra_vars $xmlsec_app check-key-data $xmlsec_params --crypto-config $crypto_config $req_key_data" >> $curlogfile
        $xmlsec_app check-key-data $xmlsec_params --crypto-config $crypto_config $req_key_data >> $curlogfile 2>> $curlogfile
        printCheckStatus $?
        res=$?
        if [ $res -ne 0 ]; then
	        cat $curlogfile >> $logfile
	        tearDownTest
            return
        fi
    fi

    # run tests

    # generate key
    if [ -n "$alg_name" -a -n "$key_name" -a "z$xmlsec_feature_gen_key" = "zyes" ]; then
        printf "    Creating new key                                      "
        params="--gen-key:$key_name $alg_name"
        if [ -f $keysfile ] ; then
            params="$params --keys-file $keysfile"
        fi
        echo "$extra_vars $VALGRIND $xmlsec_app keys $params $xmlsec_params  --crypto-config $crypto_config $keysfile" >>  $curlogfile
        $VALGRIND $xmlsec_app keys $params $xmlsec_params  --crypto-config $crypto_config $keysfile >> $curlogfile 2>> $curlogfile
        printRes $expected_res $?
        if [ $? -ne 0 ]; then
            failures=`expr $failures + 1`
        fi
    fi

    # test reading private keys
    if [ -n "$privkey_file" -a -n "$asym_key_test" ]; then
        if [ "z$xmlsec_feature_pkcs12" = "zyes" ] ; then
            printf "    Reading private key from pkcs12 file                  "
            rm -f $tmpfile
            params="--lax-key-search --pkcs12 $privkey_file.p12 $pkcs12_key_extra_options $key_test_options --output $tmpfile $asym_key_test.tmpl"
            echo "$extra_vars $VALGRIND $xmlsec_app sign $xmlsec_params --crypto-config $crypto_config $params" >>  $curlogfile
            $VALGRIND $xmlsec_app sign $xmlsec_params --crypto-config $crypto_config $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi
        if [ "z$xmlsec_feature_pkcs12_persist" = "zyes" ] ; then
            printf "    Reading private key from pkcs12 file (persist)        "
            rm -f $tmpfile
            params="--lax-key-search --pkcs12 $privkey_file.p12 $pkcs12_key_extra_options $key_test_options --output $tmpfile $asym_key_test.tmpl"
            echo "$extra_vars $VALGRIND $xmlsec_app sign $xmlsec_params --crypto-config $crypto_config $params" >>  $curlogfile
            $VALGRIND $xmlsec_app sign $xmlsec_params --crypto-config $crypto_config $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi
        if [ "z$xmlsec_feature_pkcs12_keyname" = "zyes" ] ; then
            printf "    Reading private key name from pkcs12 file             "
            rm -f $tmpfile
            params="--pkcs12 $privkey_file.p12 $pkcs12_key_extra_options $key_test_options --output $tmpfile $asym_key_test.tmpl"
            echo "$extra_vars $VALGRIND $xmlsec_app sign $xmlsec_params --crypto-config $crypto_config $params" >>  $curlogfile
            $VALGRIND $xmlsec_app sign $xmlsec_params --crypto-config $crypto_config $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi
        if [ "z$xmlsec_feature_pkcs12_keyname" = "zyes" -a "z$xmlsec_feature_pkcs12_persist" = "zyes" ] ; then
            printf "    Reading private key name from pkcs12 file (persist)   "
            rm -f $tmpfile
            params="--pkcs12-persist  --pkcs12 $privkey_file.p12 $pkcs12_key_extra_options $key_test_options --output $tmpfile $asym_key_test.tmpl"
            echo "$extra_vars $VALGRIND $xmlsec_app sign $xmlsec_params --crypto-config $crypto_config $params" >>  $curlogfile
            $VALGRIND $xmlsec_app sign $xmlsec_params --crypto-config $crypto_config $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi

        if [ "z$xmlsec_feature_openssl_store" = "zyes" ] ; then
            printf "    Reading private key from pkcs12 file using ossl-store "
            rm -f $tmpfile
            params="--lax-key-search --privkey-openssl-store $privkey_file.p12 $pkcs12_key_extra_options $key_test_options --output $tmpfile $asym_key_test.tmpl"
            echo "$extra_vars $VALGRIND $xmlsec_app sign $xmlsec_params --crypto-config $crypto_config $params" >>  $curlogfile
            $VALGRIND $xmlsec_app sign $xmlsec_params --crypto-config $crypto_config $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi

        if [ "z$xmlsec_feature_pkcs8" = "zyes" ] ; then
            printf "    Reading private key from pkcs8 pem file               "
            rm -f $tmpfile
            params="--lax-key-search --pkcs8-pem $privkey_file.p8-pem $key_test_options --output $tmpfile $asym_key_test.tmpl"
            echo "$extra_vars $VALGRIND $xmlsec_app sign $xmlsec_params --crypto-config $v $params" >>  $curlogfile
            $VALGRIND $xmlsec_app  sign $xmlsec_params --crypto-config $crypto_config $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi

        if [ "z$xmlsec_feature_pkcs8" = "zyes" ] ; then
            printf "    Reading private key from pkcs8 der file               "
            rm -f $tmpfile
            params="--lax-key-search --pkcs8-der $privkey_file.p8-der $key_test_options --output $tmpfile $asym_key_test.tmpl"
            echo "$extra_vars $VALGRIND $xmlsec_app sign $xmlsec_params --crypto-config $crypto_config $params" >>  $curlogfile
            $VALGRIND $xmlsec_app  sign $xmlsec_params --crypto-config $crypto_config $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi

        if [ "z$xmlsec_feature_privkey_pem" = "zyes" ] ; then
            printf "    Reading private key from pem file                     "
            rm -f $tmpfile
            params="--lax-key-search --privkey-pem $privkey_file.pem $key_test_options --output $tmpfile $asym_key_test.tmpl"
            echo "$extra_vars $VALGRIND $xmlsec_app sign $xmlsec_params --crypto-config $crypto_config $params" >>  $curlogfile
            $VALGRIND $xmlsec_app  sign $xmlsec_params --crypto-config $crypto_config $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi

        if [ "z$xmlsec_feature_privkey_der" = "zyes" ] ; then
            printf "    Reading private key from der file                     "
            rm -f $tmpfile
            params="--lax-key-search --privkey-der $privkey_file.der $key_test_options --output $tmpfile $asym_key_test.tmpl"
            echo "$extra_vars $VALGRIND $xmlsec_app sign $xmlsec_params --crypto-config $crypto_config $params" >>  $curlogfile
            $VALGRIND $xmlsec_app  sign $xmlsec_params --crypto-config $crypto_config $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi
    fi

    # test reading public keys
    if [ -n "$pubkey_file" -a -n "$asym_key_test" ]; then
        if [ "z$xmlsec_feature_openssl_store" = "zyes" ] ; then
            printf "    Reading public key from pem file using ossl-store     "
            rm -f $tmpfile
            params="--lax-key-search --pubkey-openssl-store $pubkey_file.pem $key_test_options $asym_key_test.xml"
            echo "$extra_vars $VALGRIND $xmlsec_app verify $xmlsec_params --crypto-config $crypto_config $params" >>  $curlogfile
            $VALGRIND $xmlsec_app verify $xmlsec_params --crypto-config $crypto_config $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi

        fi

        if [ "z$xmlsec_feature_pubkey_pem" = "zyes" ] ; then
            printf "    Reading public key from pem file                      "
            rm -f $tmpfile
            params="--lax-key-search --pubkey-pem $pubkey_file.pem $key_test_options $asym_key_test.xml"
            echo "$extra_vars $VALGRIND $xmlsec_app verify $xmlsec_params --crypto-config $crypto_config $params" >>  $curlogfile
            $VALGRIND $xmlsec_app verify $xmlsec_params --crypto-config $crypto_config $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi

        # gcrypt DER format is very basic
        if [ "z$crypto" = "zgcrypt" -a "z$req_key_data" = "zrsa" ] ; then
            pubkey_file="$pubkey_file-gcrypt"
        fi
        if [ "z$xmlsec_feature_pubkey_der" = "zyes" ] ; then
            printf "    Reading public key from der file                      "
            rm -f $tmpfile
            params="--lax-key-search --pubkey-der $pubkey_file.der $key_test_options $asym_key_test.xml"
            echo "$extra_vars $VALGRIND $xmlsec_app verify $xmlsec_params --crypto-config $crypto_config $params" >>  $curlogfile
            $VALGRIND $xmlsec_app verify $xmlsec_params --crypto-config $crypto_config $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi
    fi

    if [ -n "$certkey_file" -a -n "$asym_key_test" ]; then
        if [ "z$xmlsec_feature_cert_pem" = "zyes" ] ; then
            printf "    Reading public key from pem cert file                 "
            rm -f $tmpfile
            params="--lax-key-search --pubkey-cert-pem $certkey_file.pem $key_test_options $asym_key_test.xml"
            echo "$extra_vars $VALGRIND $xmlsec_app verify $xmlsec_params --crypto-config $crypto_config $params" >>  $curlogfile
            $VALGRIND $xmlsec_app verify $xmlsec_params --crypto-config $crypto_config $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi

        if [ "z$xmlsec_feature_cert_der" = "zyes" ] ; then
            printf "    Reading public key from der cert file                 "
            rm -f $tmpfile
            params="--lax-key-search --pubkey-cert-der $certkey_file.der $key_test_options $asym_key_test.xml"
            echo "$extra_vars $VALGRIND $xmlsec_app verify $xmlsec_params --crypto-config $crypto_config $params" >>  $curlogfile
            $VALGRIND $xmlsec_app verify $xmlsec_params --crypto-config $crypto_config $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi
    fi

    # save logs
    cat $curlogfile >> $logfile
    if [ $failures -ne 0 ] ; then
        cat $curlogfile >> $failedlogfile
    fi

    # cleanup
    tearDownTest
}

##########################################################################
##########################################################################
##########################################################################
echo "--------- Positive Testing ----------"
execKeysTest $res_success   \
    "aes"                   \
    "test-aes128"           \
    "aes-128"

execKeysTest $res_success   \
    "aes"                   \
    "test-aes192"           \
    "aes-192"

execKeysTest $res_success   \
    "aes"                   \
    "test-aes256"           \
    "aes-256"

execKeysTest $res_success   \
    "camellia"              \
    "test-camellia128"      \
    "camellia-128"

execKeysTest $res_success   \
    "camellia"              \
    "test-camellia192"      \
    "camellia-192"

execKeysTest $res_success   \
    "camellia"              \
    "test-camellia256"      \
    "camellia-256"

execKeysTest $res_success   \
    "chacha20"             \
    "test-chacha20"         \
    "chacha20-256"

execKeysTest $res_success   \
    "concatkdf"            \
    "test-concatkdf"        \
    "concatkdf-256"

execKeysTest $res_success   \
    "der-encoded-key-value" \
    ""                      \
    "der-encoded-key-value"

execKeysTest $res_success   \
    "des"                   \
    "test-des"              \
    "des-192"

# generating large dh keys takes forever
execKeysTest $res_success   \
    "dh"                    \
    ""                      \
    "dh"

execKeysTest $res_success       \
    "dsa"                       \
    "test-dsa"                  \
    "dsa-1024"                  \
    "$topfolder/keys/dsa/dsa-1024-key"    \
    "$topfolder/keys/dsa/dsa-1024-pubkey" \
    "$topfolder/keys/dsa/dsa-1024-cert"   \
    "$topfolder/aleksey-xmldsig-01/enveloped-sha1-dsa-sha1" \
    "--pwd secret123 --enabled-key-data key-name"

execKeysTest $res_success   \
    "ec"                    \
    ""                      \
    "ec"                    \
    "$topfolder/keys/ec/ec-prime256v1-key" \
    "$topfolder/keys/ec/ec-prime256v1-pubkey" \
    "$topfolder/keys/ec/ec-prime256v1-cert" \
    "$topfolder/aleksey-xmldsig-01/enveloped-sha1-ecdsa-sha1" \
    "--pwd secret123 --enabled-key-data key-name"

execKeysTest $res_success   \
    "eddsa"                \
    ""                      \
    "eddsa-ed25519"        \
    "$topfolder/keys/eddsa/eddsa-ed25519-key" \
    "$topfolder/keys/eddsa/eddsa-ed25519-pubkey" \
    "$topfolder/keys/eddsa/eddsa-ed25519-cert" \
    "$topfolder/aleksey-xmldsig-01/enveloped-sha256-eddsa-ed25519" \
    "--pwd secret123 --enabled-key-data key-name"

execKeysTest $res_success   \
    "eddsa"                \
    ""                      \
    "eddsa-ed448"          \
    "$topfolder/keys/eddsa/eddsa-ed448-key" \
    "$topfolder/keys/eddsa/eddsa-ed448-pubkey" \
    "$topfolder/keys/eddsa/eddsa-ed448-cert" \
    "$topfolder/aleksey-xmldsig-01/enveloped-sha256-eddsa-ed448" \
    "--pwd secret123 --enabled-key-data key-name"

execKeysTest $res_success   \
    "gost2001"             \
    ""                      \
    "gost-2001"            \
    "$topfolder/keys/gost/gost-2001-key" \
    "$topfolder/keys/gost/gost-2001-pubkey" \
    "$topfolder/keys/gost/gost-2001-cert" \
    "$topfolder/aleksey-xmldsig-01/enveloped-gost2001" \
    "--pwd secret123 --enabled-key-data key-name"

execKeysTest $res_success   \
    "gostr34102012-256"    \
    ""                      \
    "gost-2012-256"        \
    "$topfolder/keys/gost/gost-2012-256-key" \
    "$topfolder/keys/gost/gost-2012-256-pubkey" \
    "$topfolder/keys/gost/gost-2012-256-cert" \
    "$topfolder/aleksey-xmldsig-01/enveloped-gost2012-256" \
    "--pwd secret123 --enabled-key-data key-name"

execKeysTest $res_success   \
    "gostr34102012-512"    \
    ""                      \
    "gost-2012-512"        \
    "$topfolder/keys/gost/gost-2012-512-key" \
    "$topfolder/keys/gost/gost-2012-512-pubkey" \
    "$topfolder/keys/gost/gost-2012-512-cert" \
    "$topfolder/aleksey-xmldsig-01/enveloped-gost2012-512" \
    "--pwd secret123 --enabled-key-data key-name"

execKeysTest $res_success   \
    "hkdf"                  \
    "test-hkdf"             \
    "hkdf-256"

execKeysTest $res_success   \
    "hmac"                  \
    "test-hmac-sha1"        \
    "hmac-192"

execKeysTest $res_success   \
    "ml-dsa"                \
    ""                      \
    "ml-dsa-44"                         \
    "$topfolder/keys/ml-dsa/ml-dsa-44-key"     \
    "$topfolder/keys/ml-dsa/ml-dsa-44-pubkey"  \
    ""                      \
    "$topfolder/aleksey-xmldsig-01/enveloped-sha512-mldsa44" \
    "--pwd secret123 --enabled-key-data key-name"

execKeysTest $res_success   \
    "ml-dsa"                \
    ""                      \
    "ml-dsa-65"                         \
    "$topfolder/keys/ml-dsa/ml-dsa-65-key"     \
    "$topfolder/keys/ml-dsa/ml-dsa-65-pubkey"  \
    ""                      \
    "$topfolder/aleksey-xmldsig-01/enveloped-sha512-mldsa65" \
    "--pwd secret123 --enabled-key-data key-name"

execKeysTest $res_success   \
    "ml-dsa"                \
    ""                      \
    "ml-dsa-87"                         \
    "$topfolder/keys/ml-dsa/ml-dsa-87-key"     \
    "$topfolder/keys/ml-dsa/ml-dsa-87-pubkey"  \
    ""                      \
    "$topfolder/aleksey-xmldsig-01/enveloped-sha512-mldsa87" \
    "--pwd secret123 --enabled-key-data key-name"

execKeysTest $res_success   \
    "pbkdf2"               \
    "test-pbkdf2"          \
    "pbkdf2-256"

execKeysTest $res_success   \
    "raw-x509-cert"        \
    ""                      \
    "raw-x509-cert"

execKeysTest $res_success       \
    "rsa"                       \
    "test-rsa"                  \
    "rsa-1024"                  \
    "$topfolder/keys/rsa/rsa-4096-key"    \
    "$topfolder/keys/rsa/rsa-4096-pubkey" \
    "$topfolder/keys/rsa/rsa-4096-cert"   \
    "$topfolder/aleksey-xmldsig-01/enveloped-sha1-rsa-sha1" \
    "--pwd secret123 --enabled-key-data key-name"

execKeysTest $res_success   \
    "slh-dsa"               \
    ""                      \
    "slh-dsa-sha2-128f"                         \
    "$topfolder/keys/slh-dsa/slh-dsa-sha2-128f-key"     \
    "$topfolder/keys/slh-dsa/slh-dsa-sha2-128f-pubkey"  \
    ""                      \
    "$topfolder/aleksey-xmldsig-01/enveloped-sha512-slhdsa-sha2-128f" \
    "--pwd secret123 --enabled-key-data key-name"

execKeysTest $res_success   \
    "x509"                  \
    ""                      \
    "x509"

execKeysTest $res_success   \
    "xdh"                   \
    ""                      \
    "xdh"

##########################################################################
##########################################################################
##########################################################################
echo "--- testKeys finished ---" >> $logfile
echo "--- testKeys finished ---"
if [ -z "$XMLSEC_TEST_REPRODUCIBLE" ]; then
    echo "--- detailed log is written to  $logfile ---"
fi
