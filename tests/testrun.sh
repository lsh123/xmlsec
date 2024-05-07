#!/bin/sh

OS_ARCH=`uname -o`
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
xmlsec_params="--verbose"

#
# Prepare folders
#
if [ "z$TMPFOLDER" = "z" ] ; then
    TMPFOLDER=/tmp
fi
testname=`basename $testfile`
if test "z$OS_ARCH" = "zCygwin" || test "z$OS_ARCH" = "zMsys" ; then
    tmpfile=`cygpath -wa $TMPFOLDER/$testname.$timestamp-$$.tmp`
    logfile=`cygpath -wa $TMPFOLDER/$testname.$timestamp-$$.log`
    curlogfile=`cygpath -wa $TMPFOLDER/$testname.$timestamp-$$.cur.log`
    failedlogfile=`cygpath -wa $TMPFOLDER/$testname.$timestamp-$$.failed.log`
else
    tmpfile=$TMPFOLDER/$testname.$timestamp-$$.tmp
    logfile=$TMPFOLDER/$testname.$timestamp-$$.log
    curlogfile=$TMPFOLDER/$testname.$timestamp-$$.cur.log
    failedlogfile=$TMPFOLDER/$testname.$timestamp-$$.failed.log
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
# Setup crypto config folder
#
crypto_config_folder=$TMPFOLDER/xmlsec-crypto-config
keysfile=$crypto_config_folder/keys.xml
mkdir -p $crypto_config_folder

#
# Setup crypto engine
#
if [ "z$XMLSEC_DEFAULT_CRYPTO" != "z" ] ; then
    xmlsec_params="$xmlsec_params --crypto $XMLSEC_DEFAULT_CRYPTO"
elif [ "z$crypto" != "z" ] ; then
    xmlsec_params="$xmlsec_params --crypto $crypto"
fi

# see https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopensystemstorea
if [ "z$crypto" = "zmscng" ] ; then
    crypto_config="MY"
else
    crypto_config="$crypto_config_folder"
fi
xmlsec_params="$xmlsec_params --crypto-config $crypto_config"

# What flavour of OpenSSL do we have?
case $XMLSEC_OPENSSL_VERSION in
*LibreSSL*)
    xmlsec_openssl_flavor="libressl"
    ;;
*BoringSSL*)
    xmlsec_openssl_flavor="boringssl"
    ;;
*)
    xmlsec_openssl_flavor="openssl"
    ;;
esac

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

if [ "z$crypto" = "zopenssl" ] ; then
    # phaos certs use RSA-MD5 which might be disabled
    extra_vars="$extra_vars OPENSSL_ENABLE_MD5_VERIFY=1"
    export OPENSSL_ENABLE_MD5_VERIFY=1
fi

#
# Setup keys config
#
cert_format=$file_format

#
# On Windows, we need to force persistence for pkcs12
#
pkcs12_key_extra_options=""
if [ "z$crypto" = "zmscrypto" -o "z$crypto" = "zmscng" ] ; then
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
# GCrypt only supports DER format for now, others are good to go with certs for public keys
#
if [ "z$crypto" != "zgcrypt" ] ; then
    pub_key_option="--pubkey-cert-der"
    pub_key_format="crt"
else
    pub_key_option="--pubkey-der"
    pub_key_format="der"
fi
if [ "z$crypto" = "zgcrypt" ] ; then
    pub_key_suffix="-gcrypt"
else
    pub_key_suffix=""
fi

# On Windows, we needs to specify Crypto Service Provider (CSP)
# in the pkcs12 file to ensure it is loaded correctly to be used
# with SHA2 algorithms. Worse, the CSP is different for XP and older
# versions
if [ "z$crypto" = "zmscrypto" -o "z$crypto" = "zmscng" ] ; then
    # Samples:
    #   Cygwin	: CYGWIN_NT-5.1
    #   Msys	: MINGW32_NT-5.1
    if expr "$OS_KERNEL" : '.*_NT-5\.1' > /dev/null; then
        priv_key_suffix="-winxp"
    else
        priv_key_suffix="-win"
    fi
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
# NSS specific:
# - Cert name we need to delete for tests to work
# - Ignore NSS system policies in tests since we have legacy algorithms and small key sizes
#
NSS_TEST_CERT_NICKNAME="NSS Certificate DB:Aleksey Sanin - XML Security Library (http://www.aleksey.com/xmlsec)"
export NSS_IGNORE_SYSTEM_POLICY=1


cleanupNssCerts() {
    echo "certutil  -D -n \"$NSS_TEST_CERT_NICKNAME\" -d \"$crypto_config_folder\""  >> $logfile
    certutil  -D -n "$NSS_TEST_CERT_NICKNAME" -d "$crypto_config_folder"   >> $logfile 2>> $logfile
    if [ $? -ne 0 ]; then
        echo "--- FAILED TO DELETE TRUSTED TEST CERTIFICATE FROM NSS CERT DB. THE NEXT TEST MIGHT FAIL" >> $logfile
    fi
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

#
# Keys test function
#
execKeysTest() {
    expected_res="$1"
    req_key_data="$2"
    key_name="$3"
    alg_name="$4"
    privkey_file="$5"
    pubkey_file="$6"
    certkey_file="$7"
    asym_key_test="$8"
    key_test_options="$9"
    failures=0

    if [ -n "$XMLSEC_TEST_NAME" -a "$XMLSEC_TEST_NAME" != "$key_name" ]; then
        return
    fi

    # prepare
    rm -f $tmpfile
    old_pwd=`pwd`

    # check params
    if [ "z$expected_res" != "z$res_success" -a "z$expected_res" != "z$res_fail" ] ; then
        echo " Bad parameter: expected_res=$expected_res"
        cd $old_pwd
        return
    fi

    # starting test
    echo "Test: $alg_name $extra_message"
    echo "Test: $alg_name $extra_message -- expected $expected_res" > $curlogfile
    extra_message=""

    # check key data
    if [ -n "$req_key_data" ] ; then
        printf "    Checking required key data                            "
        echo "$extra_vars $xmlsec_app check-key-data $xmlsec_params $req_key_data" >> $curlogfile
        $xmlsec_app check-key-data $xmlsec_params $req_key_data >> $curlogfile 2>> $curlogfile
        printCheckStatus $?
        res=$?
        if [ $res -ne 0 ]; then
	        cat $curlogfile >> $logfile
	        cd $old_pwd
            return
        fi
    fi

    # run tests

    # generate key
    if [ -n "$alg_name" -a -n "$key_name" ]; then
        printf "    Creating new key                                      "
        params="--gen-key:$key_name $alg_name"
        if [ -f $keysfile ] ; then
            params="$params --keys-file $keysfile"
        fi
        echo "$extra_vars $VALGRIND $xmlsec_app keys $params $xmlsec_params $keysfile" >>  $curlogfile
        $VALGRIND $xmlsec_app keys $params $xmlsec_params $keysfile >> $curlogfile 2>> $curlogfile
        printRes $expected_res $?
        if [ $? -ne 0 ]; then
            failures=`expr $failures + 1`
        fi
    fi

    # test reading private keys
    if [ -n "$privkey_file" -a -n "$asym_key_test" ]; then
        # gcrypt doesn't support pkcs12
        if [ "z$crypto" != "zgcrypt" ] ; then
            printf "    Reading private key from pkcs12 file                  "
            rm -f $tmpfile
            params="--lax-key-search --pkcs12 $privkey_file.p12 $pkcs12_key_extra_options $key_test_options --output $tmpfile $asym_key_test.tmpl"
            echo "$extra_vars $VALGRIND $xmlsec_app sign $xmlsec_params $params" >>  $curlogfile
            $VALGRIND $xmlsec_app sign $xmlsec_params $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi
        # only gcrypt and mscrypto doesn't support keynames in pkcs12
        if [ "z$crypto" != "zgcrypt" -a "z$crypto" != "zmscrypto" ] ; then
            printf "    Reading private key name from pkcs12 file             "
            rm -f $tmpfile
            params="--pkcs12 $privkey_file.p12 $pkcs12_key_extra_options $key_test_options --output $tmpfile $asym_key_test.tmpl"
            echo "$extra_vars $VALGRIND $xmlsec_app sign $xmlsec_params $params" >>  $curlogfile
            $VALGRIND $xmlsec_app sign $xmlsec_params $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi

        # only openssl supports --privkey-openssl-store
        if [ "z$crypto" = "zopenssl" -a "z$xmlsec_openssl_flavor" != "zlibressl" -a "z$xmlsec_openssl_flavor" != "zboringssl" ] ; then
            printf "    Reading private key from pkcs12 file using ossl-store "
            rm -f $tmpfile
            params="--lax-key-search --privkey-openssl-store $privkey_file.p12 $pkcs12_key_extra_options $key_test_options --output $tmpfile $asym_key_test.tmpl"
            echo "$extra_vars $VALGRIND $xmlsec_app sign $xmlsec_params $params" >>  $curlogfile
            $VALGRIND $xmlsec_app sign $xmlsec_params $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi

        # gcrypt, mscrypto, mscng, nss don't support pkcs8
        if [ "z$crypto" != "zgcrypt" -a "z$crypto" != "znss" -a "z$crypto" != "zmscrypto" -a "z$crypto" != "zmscng" ] ; then
            printf "    Reading private key from pkcs8 pem file               "
            rm -f $tmpfile
            params="--lax-key-search --pkcs8-pem $privkey_file.p8-pem $key_test_options --output $tmpfile $asym_key_test.tmpl"
            echo "$extra_vars $VALGRIND $xmlsec_app sign $xmlsec_params $params" >>  $curlogfile
            $VALGRIND $xmlsec_app  sign $xmlsec_params $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi

        # gcrypt, mscrypto, mscng, nss don't support pkcs8
        if [ "z$crypto" != "zgcrypt" -a "z$crypto" != "znss" -a "z$crypto" != "zmscrypto" -a "z$crypto" != "zmscng" ] ; then
            printf "    Reading private key from pkcs8 der file               "
            rm -f $tmpfile
            params="--lax-key-search --pkcs8-der $privkey_file.p8-der $key_test_options --output $tmpfile $asym_key_test.tmpl"
            echo "$extra_vars $VALGRIND $xmlsec_app sign $xmlsec_params $params" >>  $curlogfile
            $VALGRIND $xmlsec_app  sign $xmlsec_params $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi

        # gcrypt doesn't support pem
        # nss, mscrypto, mscng don't like private keys in pem / der
        if [ "z$crypto" != "zgcrypt" -a "z$crypto" != "znss" -a "z$crypto" != "zmscrypto" -a "z$crypto" != "zmscng" ] ; then
            printf "    Reading private key from pem file                     "
            rm -f $tmpfile
            params="--lax-key-search --privkey-pem $privkey_file.pem $key_test_options --output $tmpfile $asym_key_test.tmpl"
            echo "$extra_vars $VALGRIND $xmlsec_app sign $xmlsec_params $params" >>  $curlogfile
            $VALGRIND $xmlsec_app  sign $xmlsec_params $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi

        # nss, mscrypto, mscng don't like private keys in pem / der
        if [ "z$crypto" != "znss"  -a "z$crypto" != "zmscrypto" -a "z$crypto" != "zmscng" ] ; then
            printf "    Reading private key from der file                     "
            rm -f $tmpfile
            params="--lax-key-search --privkey-der $privkey_file.der $key_test_options --output $tmpfile $asym_key_test.tmpl"
            echo "$extra_vars $VALGRIND $xmlsec_app sign $xmlsec_params $params" >>  $curlogfile
            $VALGRIND $xmlsec_app  sign $xmlsec_params $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi
    fi

    # test reading public keys
    if [ -n "$pubkey_file" -a -n "$asym_key_test" ]; then
        # only openssl supports --pubkey-openssl-store
        if [ "z$crypto" = "zopenssl" -a "z$xmlsec_openssl_flavor" != "zlibressl" -a "z$xmlsec_openssl_flavor" != "zboringssl" ] ; then
            printf "    Reading public key from pem file using ossl-store     "
            rm -f $tmpfile
            params="--lax-key-search --pubkey-openssl-store $pubkey_file.pem $key_test_options $asym_key_test.xml"
            echo "$extra_vars $VALGRIND $xmlsec_app verify $xmlsec_params $params" >>  $curlogfile
            $VALGRIND $xmlsec_app verify $xmlsec_params $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi

        fi

        # nss, gcrypt don't support pem
        # mscrypto, mscng don't support standalong pubkeys
        if [ "z$crypto" != "zgcrypt" -a "z$crypto" != "znss" -a "z$crypto" != "zmscrypto" -a "z$crypto" != "zmscng" ] ; then
            printf "    Reading public key from pem file                      "
            rm -f $tmpfile
            params="--lax-key-search --pubkey-pem $pubkey_file.pem $key_test_options $asym_key_test.xml"
            echo "$extra_vars $VALGRIND $xmlsec_app verify $xmlsec_params $params" >>  $curlogfile
            $VALGRIND $xmlsec_app verify $xmlsec_params $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi

        # gcrypt DER format is very basic
        if [ "z$crypto" = "zgcrypt" -a "z$req_key_data" = "zrsa" ] ; then
            pubkey_file="$pubkey_file-gcrypt"
        fi
        # mscrypto, mscng don't support standalong pubkeys
        if [ "z$crypto" != "zmscrypto" -a "z$crypto" != "zmscng" ] ; then
            printf "    Reading public key from der file                      "
            rm -f $tmpfile
            params="--lax-key-search --pubkey-der $pubkey_file.der $key_test_options $asym_key_test.xml"
            echo "$extra_vars $VALGRIND $xmlsec_app verify $xmlsec_params $params" >>  $curlogfile
            $VALGRIND $xmlsec_app verify $xmlsec_params $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi
    fi

    if [ -n "$certkey_file" -a -n "$asym_key_test" ]; then
        # gcrypt doesn't support cert
        # mscrypto, mscng don't support pem
        if [ "z$crypto" != "zgcrypt" -a "z$crypto" != "zmscrypto" -a "z$crypto" != "zmscng" ] ; then
            printf "    Reading public key from pem cert file                 "
            rm -f $tmpfile
            params="--lax-key-search --pubkey-cert-pem $certkey_file.pem $key_test_options $asym_key_test.xml"
            echo "$extra_vars $VALGRIND $xmlsec_app verify $xmlsec_params $params" >>  $curlogfile
            $VALGRIND $xmlsec_app verify $xmlsec_params $params >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
            if [ $? -ne 0 ]; then
                failures=`expr $failures + 1`
            fi
        fi

        # gcrypt doesn't support cert
        if [ "z$crypto" != "zgcrypt" ] ; then
            printf "    Reading public key from der cert file                 "
            rm -f $tmpfile
            params="--lax-key-search --pubkey-cert-der $certkey_file.der $key_test_options $asym_key_test.xml"
            echo "$extra_vars $VALGRIND $xmlsec_app verify $xmlsec_params $params" >>  $curlogfile
            $VALGRIND $xmlsec_app verify $xmlsec_params $params >> $curlogfile 2>> $curlogfile
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
    cd $old_pwd
    rm -f $tmpfile
}

#
# DSig test function
#
execDSigTest() {
    expected_res="$1"
    folder="$2"
    filename="$3"
    req_transforms="$4"
    req_key_data="$5"
    params1="$6"
    params2="$7"
    params3="$8"
    failures=0

    if [ -n "$XMLSEC_TEST_NAME" -a "$XMLSEC_TEST_NAME" != "$filename" ]; then
        return
    fi

    # prepare
    rm -f $tmpfile
    old_pwd=`pwd`

    if [ "z$crypto" = "znss" ] ; then
        cleanupNssCerts
    fi

    # check params
    if [ "z$expected_res" != "z$res_success" -a "z$expected_res" != "z$res_fail" ] ; then
        echo " Bad parameter: expected_res=$expected_res"
        cd $old_pwd
        return
    fi

    # starting test
    if [ -n "$folder" ] ; then
        cd $topfolder/$folder
        full_file=$filename
        echo "Test: $folder/$filename $extra_message"
        echo "Test: $folder/$filename in folder " `pwd` " $extra_message -- expected $expected_res" > $curlogfile
    else
        full_file=$topfolder/$filename
        echo "Test: $filename $extra_message"
        echo "Test: $folder/$filename $extra_message -- $expected_res" > $curlogfile
    fi
    extra_message=""

    # check transforms
    if [ -n "$req_transforms" ] ; then
        printf "    Checking required transforms                         "
        echo "$extra_vars $xmlsec_app check-transforms $xmlsec_params $req_transforms" >> $curlogfile
        $xmlsec_app check-transforms $xmlsec_params $req_transforms >> $curlogfile 2>> $curlogfile
        printCheckStatus $?
        res=$?
        if [ $res -ne 0 ]; then
            cat $curlogfile >> $logfile
	    cd $old_pwd
            return
        fi
    fi

    # check key data
    if [ -n "$req_key_data" ] ; then
        printf "    Checking required key data                           "
        echo "$extra_vars $xmlsec_app check-key-data $xmlsec_params $req_key_data" >> $curlogfile
        $xmlsec_app check-key-data $xmlsec_params $req_key_data >> $curlogfile 2>> $curlogfile
        printCheckStatus $?
        res=$?
        if [ $res -ne 0 ]; then
            cat $curlogfile >> $logfile
	    cd $old_pwd
            return
        fi
    fi

    # run tests
    if [ -n "$params1" ] ; then
        printf "    Verify existing signature                            "
        echo "$extra_vars $VALGRIND $xmlsec_app verify --X509-skip-strict-checks $xmlsec_params $params1 $full_file.xml" >> $curlogfile
        $VALGRIND $xmlsec_app verify --X509-skip-strict-checks $xmlsec_params $params1 $full_file.xml >> $curlogfile 2>> $curlogfile
        printRes $expected_res $?
        if [ $? -ne 0 ]; then
            failures=`expr $failures + 1`
        fi
    fi

    if [ -n "$params2" -a -z "$PERF_TEST" ] ; then
        printf "    Create new signature                                 "
        echo "$extra_vars $VALGRIND $xmlsec_app sign $xmlsec_params $params2 --output $tmpfile $full_file.tmpl" >> $curlogfile
        $VALGRIND $xmlsec_app sign $xmlsec_params $params2 --output $tmpfile $full_file.tmpl >> $curlogfile 2>> $curlogfile
        printRes $res_success $?
        if [ $? -ne 0 ]; then
            failures=`expr $failures + 1`
        fi
    fi

    if [ -n "$params3" -a -z "$PERF_TEST" ] ; then
        printf "    Verify new signature                                 "
        echo "$extra_vars $VALGRIND $xmlsec_app verify --X509-skip-strict-checks $xmlsec_params $params3 $tmpfile" >> $curlogfile
        $VALGRIND $xmlsec_app verify --X509-skip-strict-checks $xmlsec_params $params3 $tmpfile >> $curlogfile 2>> $curlogfile
        printRes $res_success $?
        if [ $? -ne  0 ]; then
            failures=`expr $failures + 1`
        fi
    fi

    # save logs
    cat $curlogfile >> $logfile
    if [ $failures -ne 0 ] ; then
        cat $curlogfile >> $failedlogfile
    fi

    # cleanup
    cd $old_pwd
    rm -f $tmpfile
}

#
# Enc test function
#
execEncTest() {
    expected_res="$1"
    folder="$2"
    filename="$3"
    req_transforms="$4"
    req_key_data="$5"
    params1="$6"
    params2="$7"
    params3="$8"
    outputTransform="$9"
    failures=0

    if [ -n "$XMLSEC_TEST_NAME" -a "$XMLSEC_TEST_NAME" != "$filename" ]; then
        return
    fi

    # prepare
    rm -f $tmpfile $tmpfile.2
    old_pwd=`pwd`


    if [ "z$crypto" = "znss" ] ; then
        cleanupNssCerts
    fi

    # check params
    if [ "z$expected_res" != "z$res_success" -a "z$expected_res" != "z$res_fail" ] ; then
        echo " Bad parameter: expected_res=$expected_res"
        cd $old_pwd
        return
    fi

    # starting test
    if [ -n "$folder" ] ; then
        cd $topfolder/$folder
        full_file=$filename
        echo "Test: $folder/$filename $extra_message"
        echo "Test: $folder/$filename in folder " `pwd` " $extra_message -- $expected_res" > $curlogfile
    else
        full_file=$topfolder/$filename
        echo "Test: $filename $extra_message"
        echo "Test: $folder/$filename $extra_message -- $expected_res" > $curlogfile
    fi
    extra_message=""

    # check transforms
    if [ -n "$req_transforms" ] ; then
        printf "    Checking required transforms                         "
        echo "$extra_vars $xmlsec_app check-transforms $xmlsec_params $req_transforms" >> $curlogfile
        $xmlsec_app check-transforms $xmlsec_params $req_transforms >> $curlogfile 2>> $curlogfile
        printCheckStatus $?
        res=$?
        if [ $res -ne 0 ]; then
	    cat $curlogfile >> $logfile
	    cd $old_pwd
            return
        fi
    fi

    # check key data
    if [ -n "$req_key_data" ] ; then
        printf "    Checking required key data                           "
        echo "$extra_vars $xmlsec_app check-key-data $xmlsec_params $req_key_data" >> $curlogfile
        $xmlsec_app check-key-data $xmlsec_params $req_key_data >> $curlogfile 2>> $curlogfile
        printCheckStatus $?
        res=$?
        if [ $res -ne 0 ]; then
            cat $curlogfile >> $logfile
	    cd $old_pwd
            return
        fi
    fi

    # run tests
    if [ -n "$params1" ] ; then
        rm -f $tmpfile
        printf "    Decrypt existing document                            "
        echo "$extra_vars $VALGRIND $xmlsec_app decrypt $xmlsec_params $params1 $full_file.xml" >>  $curlogfile
        $VALGRIND $xmlsec_app decrypt $xmlsec_params $params1 --output $tmpfile $full_file.xml >> $curlogfile  2>> $curlogfile
        res=$?
        echo "=== TEST RESULT: $res; expected: $expected_res" >> $curlogfile
        if [ $res -eq 0 -a "$expected_res" = "$res_success" ]; then
            if [ "z$outputTransform" != "z" ] ; then
                cat $tmpfile | $outputTransform > $tmpfile.2
                mv $tmpfile.2 $tmpfile
            fi
            diff $diff_param $full_file.data $tmpfile >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
        else
            printRes $expected_res $res
        fi
    	if [ $? -ne 0 ]; then
            failures=`expr $failures + 1`
    	fi
    fi

    if [ -n "$params2" -a -z "$PERF_TEST" ] ; then
        rm -f $tmpfile
        printf "    Encrypt document                                     "
        echo "$extra_vars $VALGRIND $xmlsec_app encrypt $xmlsec_params $params2 --output $tmpfile $full_file.tmpl" >>  $curlogfile
        $VALGRIND $xmlsec_app encrypt $xmlsec_params $params2 --output $tmpfile $full_file.tmpl >> $curlogfile 2>> $curlogfile
        printRes $res_success $?
        if [ $? -ne 0 ]; then
            failures=`expr $failures + 1`
        fi
    fi

    if [ -n "$params3" -a -z "$PERF_TEST" ] ; then
        rm -f $tmpfile.2
        printf "    Decrypt new document                                 "
        echo "$extra_vars $VALGRIND $xmlsec_app decrypt $xmlsec_params $params3 --output $tmpfile.2 $tmpfile" >>  $curlogfile
        $VALGRIND $xmlsec_app decrypt $xmlsec_params $params3 --output $tmpfile.2 $tmpfile >> $curlogfile 2>> $curlogfile
        res=$?
        if [ $res -eq 0 ]; then
            if [ "z$outputTransform" != "z" ] ; then
                cat $tmpfile.2 | $outputTransform > $tmpfile
                mv $tmpfile $tmpfile.2
            fi
            diff $diff_param $full_file.data $tmpfile.2 >> $curlogfile 2>> $curlogfile
            printRes $res_success $?
        else
            printRes $res_success $res
        fi
        if [ $? -ne 0 ]; then
            failures=`expr $failures + 1`
        fi
    fi

    # save logs
    cat $curlogfile >> $logfile
    if [ $failures -ne 0 ] ; then
        cat $curlogfile >> $failedlogfile
    fi

    # cleanup
    cd $old_pwd
    rm -f $tmpfile $tmpfile.2
}

# prepare
rm -rf $tmpfile $tmpfile.2 tmpfile.3

# run tests
source "$testfile"

# calculate success
percent_success=0
count_total=`expr $count_success + $count_fail + $count_skip`
if [ $count_total -gt 0 ] ; then
    percent_success=`expr 100 \* $count_success / $count_total`
fi

if [ "z$crypto" = "zopenssl" ] ; then
    min_percent_success=90
elif [ "z$crypto" = "znss" ] ; then
    min_percent_success=90
elif [ "z$crypto" = "zgnutls" ] ; then
    min_percent_success=80
elif [ "z$crypto" = "zmscng" ] ; then
    min_percent_success=80
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
