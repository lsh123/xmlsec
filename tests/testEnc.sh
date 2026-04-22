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
#
# Enc test function
#
execEncTest() {
    execEncTestWithCryptoConfig "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" ""
}

execEncTestWithCryptoConfig() {
    expected_res="$1"
    folder="$2"
    filename="$3"
    req_transforms="$4"
    req_key_data="$5"
    params1="$6"
    params2="$7"
    params3="$8"
    outputTransform="$9"
    crypto_config="${10}"
    failures=0

    if [ -n "$XMLSEC_TEST_NAME" -a "$XMLSEC_TEST_NAME" != "$filename" ]; then
        return
    fi

    # prepare
    setupTest

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
        echo "$extra_vars $xmlsec_app check-transforms $xmlsec_params  --crypto-config $crypto_config $req_transforms" >> $curlogfile
        $xmlsec_app check-transforms $xmlsec_params  --crypto-config $crypto_config $req_transforms >> $curlogfile 2>> $curlogfile
        printCheckStatus $?
        res=$?
        if [ $res -ne 0 ]; then
	        cat $curlogfile >> $logfile
	        tearDownTest
            return
        fi
    fi

    # check key data
    if [ -n "$req_key_data" ] ; then
        printf "    Checking required key data                           "
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
    xml_verification_failed="no"
    if [ -n "$params1" ] ; then
        rm -f $tmpfile
        printf "    Decrypt existing document                            "
        echo "$extra_vars $VALGRIND $xmlsec_app decrypt $xmlsec_params --crypto-config $crypto_config $params1 $full_file.xml" >>  $curlogfile
        $VALGRIND $xmlsec_app decrypt $xmlsec_params --crypto-config $crypto_config $params1 --output $tmpfile $full_file.xml >> $curlogfile  2>> $curlogfile
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
            xml_verification_failed="yes"
            failures=`expr $failures + 1`
    	fi
    fi

    if [ -n "$params2" -a -z "$PERF_TEST" ] ; then
        rm -f $tmpfile
        printf "    Encrypt document                                     "
        echo "$extra_vars $VALGRIND $xmlsec_app encrypt $xmlsec_params --crypto-config $crypto_config $params2 --output $tmpfile $full_file.tmpl" >>  $curlogfile
        $VALGRIND $xmlsec_app encrypt $xmlsec_params --crypto-config $crypto_config $params2 --output $tmpfile $full_file.tmpl >> $curlogfile 2>> $curlogfile
        printRes $res_success $?
        if [ $? -ne 0 ]; then
            failures=`expr $failures + 1`
        fi
    fi

    # update existing decryption failed
    if [  "z$XMLSEC_TEST_UPDATE_XML_ON_FAILURE" = "zyes" -a "z$xml_verification_failed" = "zyes" ] ; then
        printf "    Update existing enc document                         "
        echo "cp $tmpfile $full_file.xml" >> $curlogfile 2>> $curlogfile
        cp $tmpfile $full_file.xml
        printRes $res_success $?
        if [ $? -ne  0 ]; then
            failures=`expr $failures + 1`
        fi
    fi

    if [ -n "$params3" -a -z "$PERF_TEST" ] ; then
        rm -f $tmpfile.2
        printf "    Decrypt new document                                 "
        echo "$extra_vars $VALGRIND $xmlsec_app decrypt $xmlsec_params --crypto-config $crypto_config $params3 --output $tmpfile.2 $tmpfile" >>  $curlogfile
        $VALGRIND $xmlsec_app decrypt $xmlsec_params --crypto-config $crypto_config $params3 --output $tmpfile.2 $tmpfile >> $curlogfile 2>> $curlogfile
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
    tearDownTest
}


execEncPrintXmlDebugTest() {
    folder="$1"
    filename="$2"
    req_transforms="$3"
    req_key_data="$4"
    params1="$5"
    outputTransform="$6"
    crypto_config="$7"
    failures=0
    test_name="$filename (with --print-xml-debug)"

    if [ -n "$XMLSEC_TEST_NAME" -a "$XMLSEC_TEST_NAME" != "$test_name" ]; then
        return
    fi

    # prepare
    setupTest

    if [ "z$crypto_config" = "z" ] ; then
        crypto_config="$default_crypto_config"
    fi

    # starting test
    if [ -n "$folder" ] ; then
        cd $topfolder/$folder
        full_file=$filename
        echo "Test: $folder/$test_name $extra_message"
        echo "Test: $folder/$test_name in folder " `pwd` " $extra_message -- $res_success" > $curlogfile
    else
        full_file=$topfolder/$filename
        echo "Test: $test_name $extra_message"
        echo "Test: $test_name $extra_message -- $res_success" > $curlogfile
    fi
    extra_message=""

    # check transforms
    if [ -n "$req_transforms" ] ; then
        printf "    Checking required transforms                         "
        echo "$extra_vars $xmlsec_app check-transforms $xmlsec_params --crypto-config $crypto_config $req_transforms" >> $curlogfile
        $xmlsec_app check-transforms $xmlsec_params --crypto-config $crypto_config $req_transforms >> $curlogfile 2>> $curlogfile
        res=$?

        printCheckStatus $?
        if [ $res -ne 0 ]; then
            cat $curlogfile >> $logfile
            tearDownTest
            return
        fi
    fi

    # check key data
    if [ -n "$req_key_data" ] ; then
        printf "    Checking required key data                           "
        echo "$extra_vars $xmlsec_app check-key-data $xmlsec_params --crypto-config $crypto_config $req_key_data" >> $curlogfile
        $xmlsec_app check-key-data $xmlsec_params --crypto-config $crypto_config $req_key_data >> $curlogfile 2>> $curlogfile
        res=$?
        printCheckStatus $?
        if [ $res -ne 0 ]; then
            cat $curlogfile >> $logfile
            tearDownTest
            return
        fi
    fi

    # run test
    rm -f $tmpfile $tmpfile.3
    if [ -n "$params1" ] ; then
        printf "    Decrypt with --print-xml-debug                       "
        echo "$extra_vars $VALGRIND $xmlsec_app decrypt $xmlsec_params --print-xml-debug --crypto-config $crypto_config $params1 --output $tmpfile $full_file.xml > $tmpfile.3" >> $curlogfile
        $VALGRIND $xmlsec_app decrypt $xmlsec_params --print-xml-debug --crypto-config $crypto_config $params1 --output $tmpfile $full_file.xml > $tmpfile.3 2>> $curlogfile
        res=$?

        printCheckStatus $?
        if [ $? -ne 0 ]; then
            failures=`expr $failures + 1`
            cat $curlogfile >> $logfile
            cat $curlogfile >> $failedlogfile
            tearDownTest
            return
        fi
    fi

    # check xmllint availability for --print-xml-debug test
    if command -v xmllint >/dev/null 2>&1 ; then
        printf "    Verify --print-xml-debug output with xmllint         "
        echo "xmllint --noout $tmpfile.3" >> $curlogfile
        xmllint --noout  $tmpfile.3 >> $curlogfile 2>> $curlogfile

        res=$?

        printCheckStatus $?
        if [ $res -ne 0 ]; then
            failures=`expr $failures + 1`
            cat $curlogfile >> $logfile
            cat $curlogfile >> $failedlogfile
            tearDownTest
            return
        fi
    else
        printf "    Checking for xmllint availability                    "
        echo "Skipping test: xmllint is not available" >> $curlogfile
        printCheckStatus 1
        cat $curlogfile >> $logfile
        cat $curlogfile >> $failedlogfile
        tearDownTest
        return
    fi

    # save logs
    cat $curlogfile >> $logfile

    # cleanup
    tearDownTest
}

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
    "--aeskey:TestKeyName_GCM $topfolder/xmlenc11-interop-2012/xenc11-example-AES128-GCM.key --binary-data $topfolder/xmlenc11-interop-2012/xenc11-example-AES128-GCM.data" \
    "--aeskey:TestKeyName_GCM $topfolder/xmlenc11-interop-2012/xenc11-example-AES128-GCM.key"

if [ "z$xmlsec_feature_rsa_oaep_sha1" = "zyes" -a "z$xmlsec_feature_rsa_oaep_different_digest_and_mgf1" = "zyes" ] ; then
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

# PBKDF2 + HMAC-SHA1 + AES-256-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_pbkdf2_hmac_sha1_aes256gcm" \
    "aes256-gcm pbkdf2 hmac-sha1" \
    "derived-key" \
    "--pbkdf2-key:pbkdf2-ikm $topfolder/aleksey-xmlenc-01/pbkdf2-ikm.bin" \
    "--pbkdf2-key:pbkdf2-ikm $topfolder/aleksey-xmlenc-01/pbkdf2-ikm.bin --binary $topfolder/aleksey-xmlenc-01/enc_pbkdf2_hmac_sha1_aes256gcm.data" \
    "--pbkdf2-key:pbkdf2-ikm $topfolder/aleksey-xmlenc-01/pbkdf2-ikm.bin"

# PBKDF2 + HMAC-SHA224 + AES-256-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_pbkdf2_hmac_sha224_aes256gcm" \
    "aes256-gcm pbkdf2 hmac-sha224" \
    "derived-key" \
    "--pbkdf2-key:pbkdf2-ikm $topfolder/aleksey-xmlenc-01/pbkdf2-ikm.bin" \
    "--pbkdf2-key:pbkdf2-ikm $topfolder/aleksey-xmlenc-01/pbkdf2-ikm.bin --binary $topfolder/aleksey-xmlenc-01/enc_pbkdf2_hmac_sha224_aes256gcm.data" \
    "--pbkdf2-key:pbkdf2-ikm $topfolder/aleksey-xmlenc-01/pbkdf2-ikm.bin"

# PBKDF2 + HMAC-SHA256 + AES-256-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_pbkdf2_hmac_sha256_aes256gcm" \
    "aes256-gcm pbkdf2 hmac-sha256" \
    "derived-key" \
    "--pbkdf2-key:pbkdf2-ikm $topfolder/aleksey-xmlenc-01/pbkdf2-ikm.bin" \
    "--pbkdf2-key:pbkdf2-ikm $topfolder/aleksey-xmlenc-01/pbkdf2-ikm.bin --binary $topfolder/aleksey-xmlenc-01/enc_pbkdf2_hmac_sha256_aes256gcm.data" \
    "--pbkdf2-key:pbkdf2-ikm $topfolder/aleksey-xmlenc-01/pbkdf2-ikm.bin"

# PBKDF2 + HMAC-SHA384 + AES-256-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_pbkdf2_hmac_sha384_aes256gcm" \
    "aes256-gcm pbkdf2 hmac-sha384" \
    "derived-key" \
    "--pbkdf2-key:pbkdf2-ikm $topfolder/aleksey-xmlenc-01/pbkdf2-ikm.bin" \
    "--pbkdf2-key:pbkdf2-ikm $topfolder/aleksey-xmlenc-01/pbkdf2-ikm.bin --binary $topfolder/aleksey-xmlenc-01/enc_pbkdf2_hmac_sha384_aes256gcm.data" \
    "--pbkdf2-key:pbkdf2-ikm $topfolder/aleksey-xmlenc-01/pbkdf2-ikm.bin"

# PBKDF2 + HMAC-SHA512 + AES-256-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_pbkdf2_hmac_sha512_aes256gcm" \
    "aes256-gcm pbkdf2 hmac-sha512" \
    "derived-key" \
    "--pbkdf2-key:pbkdf2-ikm $topfolder/aleksey-xmlenc-01/pbkdf2-ikm.bin" \
    "--pbkdf2-key:pbkdf2-ikm $topfolder/aleksey-xmlenc-01/pbkdf2-ikm.bin --binary $topfolder/aleksey-xmlenc-01/enc_pbkdf2_hmac_sha512_aes256gcm.data" \
    "--pbkdf2-key:pbkdf2-ikm $topfolder/aleksey-xmlenc-01/pbkdf2-ikm.bin"

# HKDF + HMAC-SHA1 + AES-256-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_hkdf_hmac_sha1_aes256gcm" \
    "aes256-gcm hkdf hmac-sha1" \
    "derived-key" \
    "--hkdf-key:hkdf-ikm $topfolder/aleksey-xmlenc-01/hkdf-ikm.bin" \
    "--hkdf-key:hkdf-ikm $topfolder/aleksey-xmlenc-01/hkdf-ikm.bin --binary $topfolder/aleksey-xmlenc-01/enc_hkdf_hmac_sha1_aes256gcm.data" \
    "--hkdf-key:hkdf-ikm $topfolder/aleksey-xmlenc-01/hkdf-ikm.bin"

# HKDF + HMAC-SHA224 + AES-256-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_hkdf_hmac_sha224_aes256gcm" \
    "aes256-gcm hkdf hmac-sha224" \
    "derived-key" \
    "--hkdf-key:hkdf-ikm $topfolder/aleksey-xmlenc-01/hkdf-ikm.bin" \
    "--hkdf-key:hkdf-ikm $topfolder/aleksey-xmlenc-01/hkdf-ikm.bin --binary $topfolder/aleksey-xmlenc-01/enc_hkdf_hmac_sha224_aes256gcm.data" \
    "--hkdf-key:hkdf-ikm $topfolder/aleksey-xmlenc-01/hkdf-ikm.bin"

# HKDF + HMAC-SHA256 + AES-256-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_hkdf_hmac_sha256_aes256gcm" \
    "aes256-gcm hkdf hmac-sha256" \
    "derived-key" \
    "--hkdf-key:hkdf-ikm $topfolder/aleksey-xmlenc-01/hkdf-ikm.bin" \
    "--hkdf-key:hkdf-ikm $topfolder/aleksey-xmlenc-01/hkdf-ikm.bin --binary $topfolder/aleksey-xmlenc-01/enc_hkdf_hmac_sha256_aes256gcm.data" \
    "--hkdf-key:hkdf-ikm $topfolder/aleksey-xmlenc-01/hkdf-ikm.bin"

# HKDF + HMAC-SHA384 + AES-256-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_hkdf_hmac_sha384_aes256gcm" \
    "aes256-gcm hkdf hmac-sha384" \
    "derived-key" \
    "--hkdf-key:hkdf-ikm $topfolder/aleksey-xmlenc-01/hkdf-ikm.bin" \
    "--hkdf-key:hkdf-ikm $topfolder/aleksey-xmlenc-01/hkdf-ikm.bin --binary $topfolder/aleksey-xmlenc-01/enc_hkdf_hmac_sha384_aes256gcm.data" \
    "--hkdf-key:hkdf-ikm $topfolder/aleksey-xmlenc-01/hkdf-ikm.bin"

# HKDF + HMAC-SHA512 + AES-256-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_hkdf_hmac_sha512_aes256gcm" \
    "aes256-gcm hkdf hmac-sha512" \
    "derived-key" \
    "--hkdf-key:hkdf-ikm $topfolder/aleksey-xmlenc-01/hkdf-ikm.bin" \
    "--hkdf-key:hkdf-ikm $topfolder/aleksey-xmlenc-01/hkdf-ikm.bin --binary $topfolder/aleksey-xmlenc-01/enc_hkdf_hmac_sha512_aes256gcm.data" \
    "--hkdf-key:hkdf-ikm $topfolder/aleksey-xmlenc-01/hkdf-ikm.bin"

# HKDF + PRF only (no Salt, no Info, no KeyLength) + AES-256-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_hkdf_prf_only_aes256gcm" \
    "aes256-gcm hkdf hmac-sha256" \
    "derived-key" \
    "--hkdf-key:hkdf-ikm $topfolder/aleksey-xmlenc-01/hkdf-ikm.bin" \
    "--hkdf-key:hkdf-ikm $topfolder/aleksey-xmlenc-01/hkdf-ikm.bin --binary $topfolder/aleksey-xmlenc-01/enc_hkdf_prf_only_aes256gcm.data" \
    "--hkdf-key:hkdf-ikm $topfolder/aleksey-xmlenc-01/hkdf-ikm.bin"


# ECDH-ES
execEncTest $res_success \
    "" \
    "xmlenc11-interop-2012/cipherText__EC-P256__aes128-gcm__kw-aes128__ECDH-ES__ConcatKDF" \
    "aes128-gcm kw-aes128 concatkdf ecdh-es sha256" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,ec $ec_interop_priv_key_option:EC-P256 $topfolder/xmlenc11-interop-2012/EC-P256_SHA256WithECDSA-orig.$ec_interop_priv_key_format --pwd passwd" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,ec --session-key aes-128 $ec_interop_priv_key_option:EC-P256 $topfolder/xmlenc11-interop-2012/EC-P256_SHA256WithECDSA.$ec_interop_priv_key_format $pub_key_option:TestKeyName-ec-prime256v1 $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format --pwd secret123 --xml-data $topfolder/xmlenc11-interop-2012/cipherText__EC-P256__aes128-gcm__kw-aes128__ECDH-ES__ConcatKDF.data" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,ec $priv_key_option:TestKeyName-ec-prime256v1 $topfolder/keys/ec/ec-prime256v1-key.$priv_key_format  --pwd secret123"

execEncTest $res_success \
    "" \
    "xmlenc11-interop-2012/cipherText__EC-P384__aes192-gcm__kw-aes192__ECDH-ES__ConcatKDF" \
    "aes192-gcm kw-aes192 concatkdf ecdh-es sha256" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,ec  $ec_interop_priv_key_option:EC-P384 $topfolder/xmlenc11-interop-2012/EC-P384_SHA256WithECDSA-orig.$ec_interop_priv_key_format --pwd passwd" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,ec --session-key aes-192 $ec_interop_priv_key_option:EC-P384 $topfolder/xmlenc11-interop-2012/EC-P384_SHA256WithECDSA.$ec_interop_priv_key_format $pub_key_option:TestKeyName-ec-prime384v1 $topfolder/keys/ec/ec-prime384v1-pubkey.$pub_key_format --pwd secret123 --xml-data $topfolder/xmlenc11-interop-2012/cipherText__EC-P384__aes192-gcm__kw-aes192__ECDH-ES__ConcatKDF.data" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,ec $priv_key_option:TestKeyName-ec-prime384v1 $topfolder/keys/ec/ec-prime384v1-key.$priv_key_format  --pwd secret123"

execEncTest $res_success \
    "" \
    "xmlenc11-interop-2012/cipherText__EC-P521__aes256-gcm__kw-aes256__ECDH-ES__ConcatKDF" \
    "aes256-gcm kw-aes256 concatkdf ecdh-es sha256" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,ec $ec_interop_priv_key_option:EC-P521 $topfolder/xmlenc11-interop-2012/EC-P521_SHA256WithECDSA-orig.$ec_interop_priv_key_format --pwd passwd" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,ec --session-key aes-256 $ec_interop_priv_key_option:EC-P521 $topfolder/xmlenc11-interop-2012/EC-P521_SHA256WithECDSA.$ec_interop_priv_key_format $pub_key_option:TestKeyName-ec-prime521v1 $topfolder/keys/ec/ec-prime521v1-pubkey.$pub_key_format --pwd secret123 --xml-data $topfolder/xmlenc11-interop-2012/cipherText__EC-P521__aes256-gcm__kw-aes256__ECDH-ES__ConcatKDF.data" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,ec $priv_key_option:TestKeyName-ec-prime521v1 $topfolder/keys/ec/ec-prime521v1-key.$priv_key_format  --pwd secret123"

# DH-ES
execEncTest $res_success \
    "" \
    "xmlenc11-interop-2012/cipherText__DH-1024__aes128-gcm__kw-aes128__dh-es__ConcatKDF" \
    "aes128-gcm kw-aes128 concatkdf dh-es sha256" \
    "agreement-method enc-key dh" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,dh $dh_interop_priv_key_option:DH-1024 $topfolder/xmlenc11-interop-2012/DH-1024_SHA256WithDSA.$dh_interop_priv_key_format --pwd passwd" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,dh --session-key aes-128 --privkey-der:dhx-rfc5114-3-first $topfolder/keys/dhx/dhx-rfc5114-3-first-key.der --pubkey-der:dhx-rfc5114-3-second $topfolder/keys/dhx/dhx-rfc5114-3-second-pubkey.der --pwd secret123 --xml-data $topfolder/xmlenc11-interop-2012/cipherText__DH-1024__aes128-gcm__kw-aes128__dh-es__ConcatKDF.data" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,dh --privkey-der:dhx-rfc5114-3-second $topfolder/keys/dhx/dhx-rfc5114-3-second-key.der --pwd secret123"



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
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha1_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format"
# ECDH + ConcatKDF + SHA2
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha224_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es concatkdf sha224" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha224_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha256_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es concatkdf sha256" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha256_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha384_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es concatkdf sha384" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha384_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha512_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es concatkdf sha512" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha512_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format"

# ECDH + ConcatKDF + SHA3
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha3_224_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es concatkdf sha3-224" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha3_224_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha3_256_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es concatkdf sha3-256" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha3_256_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha3_384_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es concatkdf sha3-384" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha3_384_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha3_512_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es concatkdf sha3-512" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_concatkdf_sha3_512_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format"

# ECDH-P384 + ConcatKDF + SHA384 + KW-AES192 + AES192-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p384_concatkdf_sha384_kw_aes192_aes192gcm" \
    "aes192-gcm kw-aes192 ecdh-es concatkdf sha384" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime384v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime384v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-192 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime384v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime384v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p384_concatkdf_sha384_kw_aes192_aes192gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime384v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime384v1-pubkey.$pub_key_format"

# ECDH-P521 + ConcatKDF + SHA512 + KW-AES256 + AES256-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p521_concatkdf_sha512_kw_aes256_aes256gcm" \
    "aes256-gcm kw-aes256 ecdh-es concatkdf sha512" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime521v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime521v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime521v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime521v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p521_concatkdf_sha512_kw_aes256_aes256gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime521v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime521v1-pubkey.$pub_key_format"

# DH-ES + ConcatKDF + SHA256 + KW-AES128 + AES128-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_dh_concatkdf_sha256_kw_aes128_aes128gcm" \
    "aes128-gcm kw-aes128 concatkdf dh-es sha256" \
    "agreement-method enc-key dh" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,dh $dhx_priv_key_option:dhx-rfc5114-3-second $topfolder/keys/dhx/dhx-rfc5114-3-second-key.$dhx_priv_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,dh --session-key aes-128 $dhx_priv_key_option:dhx-rfc5114-3-first $topfolder/keys/dhx/dhx-rfc5114-3-first-key.$dhx_priv_key_format $dhx_pub_key_option:dhx-rfc5114-3-second $topfolder/keys/dhx/dhx-rfc5114-3-second-pubkey.$dhx_pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_dh_concatkdf_sha256_kw_aes128_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-value,key-name,dh $dhx_priv_key_option:dhx-rfc5114-3-second $topfolder/keys/dhx/dhx-rfc5114-3-second-key.$dhx_priv_key_format"

# ECDH + PBKDF2+SHA1
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha1_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es pbkdf2 hmac-sha1" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha1_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format"

# ECDH + PBKDF2+SHA2
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha224_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es pbkdf2 hmac-sha224" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha224_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha256_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es pbkdf2 hmac-sha256" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha256_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha384_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es pbkdf2 hmac-sha384" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha384_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha512_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 ecdh-es pbkdf2 hmac-sha512" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-256 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_pbkdf2_1000_hmac_sha512_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format"

# ECDH + HKDF + SHA256
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_hkdf_sha256_kw_aes256_aes128gcm" \
    "aes128-gcm kw-aes256 ecdh-es hkdf hmac-sha256" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-128 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_hkdf_sha256_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format"

# ECDH + HKDF + SHA384
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_hkdf_sha384_kw_aes256_aes128gcm" \
    "aes128-gcm kw-aes256 ecdh-es hkdf hmac-sha384" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-128 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_hkdf_sha384_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format"

# ECDH + HKDF + SHA512
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_ecdh_p256_hkdf_sha512_kw_aes256_aes128gcm" \
    "aes128-gcm kw-aes256 ecdh-es hkdf hmac-sha512" \
    "agreement-method enc-key ec" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec --session-key aes-128 $priv_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-key.$priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_ecdh_p256_hkdf_sha512_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,ec $priv_key_option:recipient-key-name $topfolder/keys/ec/ec-prime256v1-second-key.$priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/ec/ec-prime256v1-pubkey.$pub_key_format"

# X25519 + ConcatKDF + SHA2
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_xdh_x25519_concatkdf_sha256_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 x25519 concatkdf sha256" \
    "agreement-method enc-key xdh" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x25519-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x25519-first-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh --session-key aes-256 $xdh_priv_key_option:originator-key-name $topfolder/keys/xdh/xdh-x25519-first-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x25519-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_xdh_x25519_concatkdf_sha256_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x25519-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x25519-first-pubkey.$pub_key_format"

# X448 + ConcatKDF + SHA2
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_xdh_x448_concatkdf_sha256_kw_aes256_aes128gcm" \
    "aes256-gcm kw-aes256 x448 concatkdf sha256" \
    "agreement-method enc-key xdh" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x448-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x448-first-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh --session-key aes-256 $xdh_priv_key_option:originator-key-name $topfolder/keys/xdh/xdh-x448-first-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x448-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_xdh_x448_concatkdf_sha256_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x448-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x448-first-pubkey.$pub_key_format"

# X25519 + ConcatKDF + SHA384 + KW-AES256 + AES128-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_xdh_x25519_concatkdf_sha384_kw_aes256_aes128gcm" \
    "aes128-gcm kw-aes256 x25519 concatkdf sha384" \
    "agreement-method enc-key xdh" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x25519-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x25519-first-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh --session-key aes-256 $xdh_priv_key_option:originator-key-name $topfolder/keys/xdh/xdh-x25519-first-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x25519-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_xdh_x25519_concatkdf_sha384_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x25519-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x25519-first-pubkey.$pub_key_format"

# X448 + ConcatKDF + SHA384 + KW-AES256 + AES128-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_xdh_x448_concatkdf_sha384_kw_aes256_aes128gcm" \
    "aes128-gcm kw-aes256 x448 concatkdf sha384" \
    "agreement-method enc-key xdh" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x448-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x448-first-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh --session-key aes-256 $xdh_priv_key_option:originator-key-name $topfolder/keys/xdh/xdh-x448-first-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x448-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_xdh_x448_concatkdf_sha384_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x448-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x448-first-pubkey.$pub_key_format"

# X25519 + HKDF + SHA256 + KW-AES256 + AES128-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_xdh_x25519_hkdf_sha256_kw_aes256_aes128gcm" \
    "aes128-gcm kw-aes256 x25519 hkdf hmac-sha256" \
    "agreement-method enc-key xdh" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x25519-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x25519-first-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh --session-key aes-128 $xdh_priv_key_option:originator-key-name $topfolder/keys/xdh/xdh-x25519-first-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x25519-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_xdh_x25519_hkdf_sha256_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x25519-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x25519-first-pubkey.$pub_key_format"

# X448 + HKDF + SHA256 + KW-AES256 + AES128-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_xdh_x448_hkdf_sha256_kw_aes256_aes128gcm" \
    "aes128-gcm kw-aes256 x448 hkdf hmac-sha256" \
    "agreement-method enc-key xdh" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x448-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x448-first-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh --session-key aes-128 $xdh_priv_key_option:originator-key-name $topfolder/keys/xdh/xdh-x448-first-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x448-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_xdh_x448_hkdf_sha256_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x448-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x448-first-pubkey.$pub_key_format"

# X25519 + HKDF + SHA384 + KW-AES256 + AES128-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_xdh_x25519_hkdf_sha384_kw_aes256_aes128gcm" \
    "aes128-gcm kw-aes256 x25519 hkdf hmac-sha384" \
    "agreement-method enc-key xdh" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x25519-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x25519-first-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh --session-key aes-128 $xdh_priv_key_option:originator-key-name $topfolder/keys/xdh/xdh-x25519-first-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x25519-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_xdh_x25519_hkdf_sha384_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x25519-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x25519-first-pubkey.$pub_key_format"

# X448 + HKDF + SHA384 + KW-AES256 + AES128-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_xdh_x448_hkdf_sha384_kw_aes256_aes128gcm" \
    "aes128-gcm kw-aes256 x448 hkdf hmac-sha384" \
    "agreement-method enc-key xdh" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x448-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x448-first-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh --session-key aes-128 $xdh_priv_key_option:originator-key-name $topfolder/keys/xdh/xdh-x448-first-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x448-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_xdh_x448_hkdf_sha384_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x448-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x448-first-pubkey.$pub_key_format"

# X25519 + HKDF + SHA512 + KW-AES256 + AES128-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_xdh_x25519_hkdf_sha512_kw_aes256_aes128gcm" \
    "aes128-gcm kw-aes256 x25519 hkdf hmac-sha512" \
    "agreement-method enc-key xdh" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x25519-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x25519-first-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh --session-key aes-128 $xdh_priv_key_option:originator-key-name $topfolder/keys/xdh/xdh-x25519-first-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x25519-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_xdh_x25519_hkdf_sha512_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x25519-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x25519-first-pubkey.$pub_key_format"

# X448 + HKDF + SHA512 + KW-AES256 + AES128-GCM
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc_xdh_x448_hkdf_sha512_kw_aes256_aes128gcm" \
    "aes128-gcm kw-aes256 x448 hkdf hmac-sha512" \
    "agreement-method enc-key xdh" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x448-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x448-first-pubkey.$pub_key_format" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh --session-key aes-128 $xdh_priv_key_option:originator-key-name $topfolder/keys/xdh/xdh-x448-first-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x448-second-pubkey.$pub_key_format --xml-data $topfolder/aleksey-xmlenc-01/enc_xdh_x448_hkdf_sha512_kw_aes256_aes128gcm.data" \
    "--enabled-key-data agreement-method,enc-key,key-name,key-value,xdh $xdh_priv_key_option:recipient-key-name $topfolder/keys/xdh/xdh-x448-second-key.$xdh_priv_key_format --pwd secret123 $pub_key_option:originator-key-name $topfolder/keys/xdh/xdh-x448-first-pubkey.$pub_key_format"

if [ "z$xmlsec_feature_x509_data_lookup" = "zyes" ] ; then
    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_subject_name" \
        "aes256-cbc rsa-1_5" \
        "x509" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/rsa/rsa-4096-cert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_subject_name.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_issuer_name_serial" \
        "aes256-cbc rsa-1_5" \
        "x509" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/rsa/rsa-4096-cert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_issuer_name_serial.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_ski" \
        "aes256-cbc rsa-1_5" \
        "x509" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/rsa/rsa-4096-cert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_ski.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha1" \
        "aes256-cbc rsa-1_5 sha1" \
        "x509" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/rsa/rsa-4096-cert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha1.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha224" \
        "aes256-cbc rsa-1_5 sha224" \
        "x509" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/rsa/rsa-4096-cert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha224.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha256" \
        "aes256-cbc rsa-1_5 sha256" \
        "x509" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/rsa/rsa-4096-cert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha256.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha384" \
        "aes256-cbc rsa-1_5 sha384" \
        "x509" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/rsa/rsa-4096-cert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha384.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha512" \
        "aes256-cbc rsa-1_5 sha512" \
        "x509" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/rsa/rsa-4096-cert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha512.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha3_224" \
        "aes256-cbc rsa-1_5 sha3-224" \
        "x509" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/rsa/rsa-4096-cert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha3_224.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha3_256" \
        "aes256-cbc rsa-1_5 sha3-256" \
        "x509" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/rsa/rsa-4096-cert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha3_256.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha3_384" \
        "aes256-cbc rsa-1_5 sha3-384" \
        "x509" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/rsa/rsa-4096-cert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha3_384.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha3_512" \
        "aes256-cbc rsa-1_5 sha3-512" \
        "x509" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "--session-key aes-256 --pubkey-cert-$cert_format $topfolder/keys/rsa/rsa-4096-cert.$cert_format --xml-data $topfolder/aleksey-xmlenc-01/enc_rsa_1_5_x509_digest_sha3_512.data --node-name http://example.org/paymentv2:CreditCard" \
        "$priv_key_option $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"
fi

# same file is encrypted with two keys, test both
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-two-enc-keys" \
    "aes256-cbc rsa-1_5" \
    "x509" \
    "$priv_key_option:TestKeyName-rsa-2048 $topfolder/keys/rsa/rsa-2048-key.$priv_key_format --pwd secret123" \
    "--session-key aes-256 --xml-data $topfolder/aleksey-xmlenc-01/enc-two-enc-keys.data --pubkey-cert-$cert_format:TestKeyName-rsa-2048 $topfolder/keys/rsa/rsa-2048-cert.$cert_format --pubkey-cert-$cert_format:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-cert.$cert_format" \
    "$priv_key_option:TestKeyName-rsa-2048 $topfolder/keys/rsa/rsa-2048-key.$priv_key_format --pwd secret123"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-two-enc-keys" \
    "aes256-cbc rsa-1_5" \
    "x509" \
    "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
    "--session-key aes-256 --xml-data $topfolder/aleksey-xmlenc-01/enc-two-enc-keys.data --pubkey-cert-$cert_format:TestKeyName-rsa-2048 $topfolder/keys/rsa/rsa-2048-cert.$cert_format --pubkey-cert-$cert_format:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-cert.$cert_format" \
    "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"


execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/large_input" \
    "aes256-cbc rsa-1_5" \
    "x509" \
    "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
    "--session-key aes-256 --xml-data $topfolder/aleksey-xmlenc-01/large_input.data --pubkey-cert-$cert_format:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-cert.$cert_format" \
    "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-element-isolatin1" \
    "aes256-cbc rsa-1_5" \
    "x509" \
    "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
    "--session-key aes-256 --xml-data $topfolder/aleksey-xmlenc-01/enc-element-isolatin1.data --pubkey-cert-$cert_format:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-cert.$cert_format" \
    "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-content-isolatin1" \
    "aes256-cbc rsa-1_5" \
    "x509" \
    "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
    "--session-key aes-256 --xml-data $topfolder/aleksey-xmlenc-01/enc-content-isolatin1.data --node-name http://example.org/paymentv2:CreditCard --pubkey-cert-$cert_format:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-cert.$cert_format" \
    "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-keyname" \
    "tripledes-cbc" \
    "" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml --binary-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-keyname.data" \
    "--keys-file $topfolder/keys/keys.xml"

extra_message="Test '--des-key' option"
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-keyname" \
    "tripledes-cbc" \
    "" \
    "--des-key:test-des $topfolder/aleksey-xmlenc-01/test-des.bin" \
    "--des-key:test-des $topfolder/aleksey-xmlenc-01/test-des.bin --binary-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-keyname.data" \
    "--des-key:test-des $topfolder/aleksey-xmlenc-01/test-des.bin"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-keyname2" \
    "tripledes-cbc" \
    "" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml --binary-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-keyname2.data" \
    "--keys-file $topfolder/keys/keys.xml"


execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes128cbc-keyname" \
    "aes128-cbc" \
    "" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml --binary-data $topfolder/aleksey-xmlenc-01/enc-aes128cbc-keyname.data" \
    "--keys-file $topfolder/keys/keys.xml"

extra_message="Test '--aes-key' option"
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes128cbc-keyname" \
    "aes128-cbc" \
    "" \
    "--aes-key:test-aes128 $topfolder/aleksey-xmlenc-01/test-aes128.bin" \
    "--aes-key:test-aes128 $topfolder/aleksey-xmlenc-01/test-aes128.bin --binary-data $topfolder/aleksey-xmlenc-01/enc-aes128cbc-keyname.data" \
    "--aes-key:test-aes128 $topfolder/aleksey-xmlenc-01/test-aes128.bin"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes192cbc-keyname" \
    "aes192-cbc" \
    "" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml --binary-data $topfolder/aleksey-xmlenc-01/enc-aes192cbc-keyname.data" \
    "--keys-file $topfolder/keys/keys.xml"

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
    "--keys-file $topfolder/keys/keys.xml --binary-data $topfolder/aleksey-xmlenc-01/enc-aes256cbc-keyname.data" \
    "--keys-file $topfolder/keys/keys.xml"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes128gcm-keyname" \
    "aes128-gcm" \
    "" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml --binary-data $topfolder/aleksey-xmlenc-01/enc-aes128gcm-keyname.data" \
    "--keys-file $topfolder/keys/keys.xml"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes192gcm-keyname" \
    "aes192-gcm" \
    "" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml --binary-data $topfolder/aleksey-xmlenc-01/enc-aes192gcm-keyname.data" \
    "--keys-file $topfolder/keys/keys.xml"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes256gcm-keyname" \
    "aes256-gcm" \
    "" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml --binary-data $topfolder/aleksey-xmlenc-01/enc-aes256gcm-keyname.data" \
    "--keys-file $topfolder/keys/keys.xml"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-camellia128cbc-keyname" \
    "camellia128-cbc" \
    "" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml --binary-data $topfolder/aleksey-xmlenc-01/enc-camellia128cbc-keyname.data" \
    "--keys-file $topfolder/keys/keys.xml"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-camellia192cbc-keyname" \
    "camellia192-cbc" \
    "" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml --binary-data $topfolder/aleksey-xmlenc-01/enc-camellia192cbc-keyname.data" \
    "--keys-file $topfolder/keys/keys.xml"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-camellia256cbc-keyname" \
    "camellia256-cbc" \
    "" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml --binary-data $topfolder/aleksey-xmlenc-01/enc-camellia256cbc-keyname.data" \
    "--keys-file $topfolder/keys/keys.xml"


extra_message="Test '--camellia-key' option"
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-camellia256cbc-keyname" \
    "camellia256-cbc" \
    "" \
    "--camellia-key:test-camellia256 $topfolder/aleksey-xmlenc-01/test-camellia256.bin" \
    "--camellia-key:test-camellia256 $topfolder/aleksey-xmlenc-01/test-camellia256.bin --binary-data $topfolder/aleksey-xmlenc-01/enc-camellia256cbc-keyname.data" \
    "--camellia-key:test-camellia256 $topfolder/aleksey-xmlenc-01/test-camellia256.bin"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-camellia128cbc-kw-camellia256-keyname" \
    "camellia128-cbc kw-camellia256" \
    "enc-key camellia" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml  --session-key camellia-128  --binary-data $topfolder/aleksey-xmlenc-01/enc-camellia128cbc-kw-camellia256-keyname.data" \
    "--keys-file $topfolder/keys/keys.xml"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-camellia128cbc-kw-camellia128-keyname" \
    "camellia128-cbc kw-camellia128" \
    "enc-key camellia" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml --session-key camellia-128 --binary-data $topfolder/aleksey-xmlenc-01/enc-camellia128cbc-kw-camellia128-keyname.data" \
    "--keys-file $topfolder/keys/keys.xml"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-camellia128cbc-kw-camellia192-keyname" \
    "camellia128-cbc kw-camellia192" \
    "enc-key camellia" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml --session-key camellia-128 --binary-data $topfolder/aleksey-xmlenc-01/enc-camellia128cbc-kw-camellia192-keyname.data" \
    "--keys-file $topfolder/keys/keys.xml"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-chacha20-keyname" \
    "chacha20" \
    "" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml --binary-data $topfolder/aleksey-xmlenc-01/enc-chacha20-keyname.data" \
    "--keys-file $topfolder/keys/keys.xml"

extra_message="Test '--chacha20-key' option"
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-chacha20-keyname" \
    "chacha20" \
    "" \
    "--chacha20-key:test-chacha20 $topfolder/aleksey-xmlenc-01/test-chacha20.bin" \
    "--chacha20-key:test-chacha20 $topfolder/aleksey-xmlenc-01/test-chacha20.bin --binary-data $topfolder/aleksey-xmlenc-01/enc-chacha20-keyname.data" \
    "--chacha20-key:test-chacha20 $topfolder/aleksey-xmlenc-01/test-chacha20.bin"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-chacha20-keyname-missing-nonce" \
    "chacha20" \
    "" \
    "" \
    "--keys-file $topfolder/keys/keys.xml --binary-data $topfolder/aleksey-xmlenc-01/enc-chacha20-keyname-missing-nonce.data" \
    "--keys-file $topfolder/keys/keys.xml"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-chacha20poly1305-keyname" \
    "chacha20-poly1305" \
    "" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml --binary-data $topfolder/aleksey-xmlenc-01/enc-chacha20poly1305-keyname.data" \
    "--keys-file $topfolder/keys/keys.xml"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-chacha20poly1305-keyname-missing-nonce" \
    "chacha20-poly1305" \
    "" \
    "" \
    "--keys-file $topfolder/keys/keys.xml --binary-data $topfolder/aleksey-xmlenc-01/enc-chacha20poly1305-keyname-missing-nonce.data" \
    "--keys-file $topfolder/keys/keys.xml"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-chacha20poly1305-aad-keyname" \
    "chacha20-poly1305" \
    "" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml --binary-data $topfolder/aleksey-xmlenc-01/enc-chacha20poly1305-aad-keyname.data" \
    "--keys-file $topfolder/keys/keys.xml"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-keyname-content" \
    "tripledes-cbc" \
    " " \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml --xml-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-keyname-content.data --node-id Test" \
    "--keys-file $topfolder/keys/keys.xml"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-keyname-element" \
    "tripledes-cbc" \
    " " \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml --xml-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-keyname-element.data --node-id Test" \
    "--keys-file $topfolder/keys/keys.xml"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-keyname-element-root" \
    "tripledes-cbc" \
    " " \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml --xml-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-keyname-element-root.data --node-id Test" \
    "--keys-file $topfolder/keys/keys.xml"

execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-des3cbc-aes192-keyname" \
    "tripledes-cbc kw-aes192" \
    "enc-key aes des" \
    "--keys-file $topfolder/keys/keys.xml" \
    "--keys-file $topfolder/keys/keys.xml  --session-key des-192  --binary-data $topfolder/aleksey-xmlenc-01/enc-des3cbc-aes192-keyname.data" \
    "--keys-file $topfolder/keys/keys.xml"

if [ "z$xmlsec_feature_rsa_oaep_sha1" = "zyes" ] ; then
    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1-params" \
        "aes256-cbc rsa-oaep-mgf1p sha1" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1-params.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1" \
        "aes256-cbc rsa-oaep-mgf1p sha1 sha1" \
        " " \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    # verify that XML debug output is correct and contains the expected elements and values
    execEncPrintXmlDebugTest \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1" \
        "aes256-cbc rsa-oaep-mgf1p sha1 sha1" \
        " " \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"
fi

if [  "z$xmlsec_feature_rsa_oaep_sha1" = "zyes" -a "z$xmlsec_feature_rsa_oaep_different_digest_and_mgf1" = "zyes" ] ; then
    # various digest and default mgf1 (sha1)
    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_md5" \
        "aes256-cbc rsa-oaep-mgf1p md5 sha1" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_md5.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_ripemd160" \
        "aes256-cbc rsa-oaep-mgf1p ripemd160 sha1" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_ripemd160.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha224" \
        "aes256-cbc rsa-oaep-mgf1p sha224 sha1" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha224.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha256" \
        "aes256-cbc rsa-oaep-mgf1p sha256 sha1" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha256.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha384" \
        "aes256-cbc rsa-oaep-mgf1p sha384 sha1" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha384.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512" \
        "aes256-cbc rsa-oaep-mgf1p sha512 sha1" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    # SHA3 digest variants with default mgf1 (sha1)
    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha3_224" \
        "aes256-cbc rsa-oaep-mgf1p sha3-224 sha1" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha3_224.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha3_256" \
        "aes256-cbc rsa-oaep-mgf1p sha3-256 sha1" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha3_256.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha3_384" \
        "aes256-cbc rsa-oaep-mgf1p sha3-384 sha1" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha3_384.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha3_512" \
        "aes256-cbc rsa-oaep-mgf1p sha3-512 sha1" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha3_512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    # various digest and mgf1=sha512
    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_md5_mgf1_sha512" \
        "aes256-cbc rsa-oaep-mgf1p md5 sha512" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_md5_mgf1_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_ripemd160_mgf1_sha512" \
        "aes256-cbc rsa-oaep-mgf1p ripemd160 sha512" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_ripemd160_mgf1_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    if [ "z$xmlsec_feature_rsa_oaep_sha1" = "zyes" ] ; then
        execEncTest $res_success \
            "" \
            "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1_mgf1_sha512" \
            "aes256-cbc rsa-oaep-mgf1p sha1 sha512" \
            "" \
            "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
            "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1_mgf1_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
            "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"
    fi

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha224_mgf1_sha512" \
        "aes256-cbc rsa-oaep-mgf1p sha224 sha512" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha224_mgf1_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha256_mgf1_sha512" \
        "aes256-cbc rsa-oaep-mgf1p sha256 sha512" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha256_mgf1_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha384_mgf1_sha512" \
        "aes256-cbc rsa-oaep-mgf1p sha384 sha512" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha384_mgf1_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    # digest=sha512 and various mgf1
    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha1" \
        "aes256-cbc rsa-oaep-mgf1p sha512 sha1" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha224" \
        "aes256-cbc rsa-oaep-mgf1p sha512 sha224" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha224.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha256" \
        "aes256-cbc rsa-oaep-mgf1p sha512 sha256" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha256.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha384" \
        "aes256-cbc rsa-oaep-mgf1p sha512 sha384" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha384.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"
fi

# same algo for both digest and MGF1
if [ "z$xmlsec_feature_rsa_oaep_sha1" = "zyes" ] ; then
    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1_mgf1_sha1" \
        "aes256-cbc rsa-oaep-mgf1p sha1 sha1" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha1_mgf1_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"
fi

if [ "z$xmlsec_feature_rsa_oaep_sha224" = "zyes" ] ; then
    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha224_mgf1_sha224" \
        "aes256-cbc rsa-oaep-mgf1p sha224 sha224" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key$priv_key_suffix.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha224_mgf1_sha224.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key$priv_key_suffix.$priv_key_format --pwd secret123"
fi

if [ "z$xmlsec_feature_rsa_oaep_sha256" = "zyes" ] ; then
    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha256_mgf1_sha256" \
        "aes256-cbc rsa-oaep-mgf1p sha256 sha256" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key$priv_key_suffix.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha256_mgf1_sha256.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key$priv_key_suffix.$priv_key_format --pwd secret123"
fi

if [ "z$xmlsec_feature_rsa_oaep_sha384" = "zyes" ] ; then
    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha384_mgf1_sha384" \
        "aes256-cbc rsa-oaep-mgf1p sha384 sha384" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key$priv_key_suffix.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha384_mgf1_sha384.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key$priv_key_suffix.$priv_key_format --pwd secret123"
fi

if [ "z$xmlsec_feature_rsa_oaep_sha512" = "zyes" ] ; then
    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha512" \
        "aes256-cbc rsa-oaep-mgf1p sha512 sha512" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key$priv_key_suffix.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_sha512_mgf1_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key$priv_key_suffix.$priv_key_format --pwd secret123"

    # RSA OAEP XMLEnc 1.1 transform (exactly same as 1.0 but different URL)
    execEncTest $res_success \
        "" \
        "aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_enc11_sha512_mgf1_sha512" \
        "aes256-cbc rsa-oaep-enc11 sha512 sha512" \
        "" \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key$priv_key_suffix.$priv_key_format --pwd secret123" \
        "$pub_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-pubkey$rsa_pub_key_suffix.$pub_key_format --session-key aes-256 --enabled-key-data key-name,enc-key --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-kt-rsa_oaep_enc11_sha512_mgf1_sha512.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:TestKeyName-rsa-4096 $topfolder/keys/rsa/rsa-4096-key$priv_key_suffix.$priv_key_format --pwd secret123"
fi

# same test but decrypt using two different keys
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-two-recipients" \
    "tripledes-cbc rsa-1_5" \
    "x509" \
    "--lax-key-search $priv_key_option:pub1 $topfolder/keys/rsa/rsa-2048-key.$priv_key_format --pwd secret123" \
    "--pubkey-cert-$cert_format:pub1 $topfolder/keys/rsa/rsa-2048-cert.$cert_format --pubkey-cert-$cert_format:pub2 $topfolder/keys/rsa/rsa-4096-cert.$cert_format --session-key des-192 --xml-data $topfolder/aleksey-xmlenc-01/enc-two-recipients.data" \
    "--lax-key-search $priv_key_option:pub1 $topfolder/keys/rsa/rsa-2048-key.$priv_key_format --pwd secret123"
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-two-recipients" \
    "tripledes-cbc rsa-1_5" \
    "x509" \
    "--lax-key-search $priv_key_option:pub1 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123" \
    "--pubkey-cert-$cert_format:pub1 $topfolder/keys/rsa/rsa-2048-cert.$cert_format --pubkey-cert-$cert_format:pub2 $topfolder/keys/rsa/rsa-4096-cert.$cert_format --session-key des-192 --xml-data $topfolder/aleksey-xmlenc-01/enc-two-recipients.data" \
    "--lax-key-search $priv_key_option:pub1 $topfolder/keys/rsa/rsa-4096-key.$priv_key_format --pwd secret123"

##########################################################################
#
# ML-KEM (Key Encapsulation Mechanism, EncapsulationMechanism)
#
##########################################################################
if [ "z$xmlsec_feature_ml_kem" = "zyes" ] ; then
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes256-em-ml-kem-512" \
    "aes256-cbc ml-kem-512" \
    "ml-kem" \
    "$mlkem_priv_key_option:TestKeyName-ml-kem-512 $topfolder/keys/ml-kem/ml-kem-512-key.$mlkem_priv_key_format --pwd secret123 --enabled-key-data key-name,encapsulation-mechanism" \
    "$mlkem_pub_key_option:TestKeyName-ml-kem-512 $topfolder/keys/ml-kem/ml-kem-512-pubkey.$mlkem_pub_key_format --enabled-key-data key-name,encapsulation-mechanism --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-em-ml-kem-512.data --node-name http://example.org/paymentv2:CreditCard" \
    "$mlkem_priv_key_option:TestKeyName-ml-kem-512 $topfolder/keys/ml-kem/ml-kem-512-key.$mlkem_priv_key_format --pwd secret123 --enabled-key-data key-name,encapsulation-mechanism"
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes256-em-ml-kem-768" \
    "aes256-cbc ml-kem-768" \
    "ml-kem" \
    "$mlkem_priv_key_option:TestKeyName-ml-kem-768 $topfolder/keys/ml-kem/ml-kem-768-key.$mlkem_priv_key_format --pwd secret123 --enabled-key-data key-name,encapsulation-mechanism" \
    "$mlkem_pub_key_option:TestKeyName-ml-kem-768 $topfolder/keys/ml-kem/ml-kem-768-pubkey.$mlkem_pub_key_format --enabled-key-data key-name,encapsulation-mechanism --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-em-ml-kem-768.data --node-name http://example.org/paymentv2:CreditCard" \
    "$mlkem_priv_key_option:TestKeyName-ml-kem-768 $topfolder/keys/ml-kem/ml-kem-768-key.$mlkem_priv_key_format --pwd secret123 --enabled-key-data key-name,encapsulation-mechanism"
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes256-em-ml-kem-1024" \
    "aes256-cbc ml-kem-1024" \
    "ml-kem" \
    "$mlkem_priv_key_option:TestKeyName-ml-kem-1024 $topfolder/keys/ml-kem/ml-kem-1024-key.$mlkem_priv_key_format --pwd secret123 --enabled-key-data key-name,encapsulation-mechanism" \
    "$mlkem_pub_key_option:TestKeyName-ml-kem-1024 $topfolder/keys/ml-kem/ml-kem-1024-pubkey.$mlkem_pub_key_format --enabled-key-data key-name,encapsulation-mechanism --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256-em-ml-kem-1024.data --node-name http://example.org/paymentv2:CreditCard" \
    "$mlkem_priv_key_option:TestKeyName-ml-kem-1024 $topfolder/keys/ml-kem/ml-kem-1024-key.$mlkem_priv_key_format --pwd secret123 --enabled-key-data key-name,encapsulation-mechanism"
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes128gcm-em-ml-kem-512" \
    "aes128-gcm ml-kem-512" \
    "ml-kem" \
    "$mlkem_priv_key_option:TestKeyName-ml-kem-512 $topfolder/keys/ml-kem/ml-kem-512-key.$mlkem_priv_key_format --pwd secret123 --enabled-key-data key-name,encapsulation-mechanism" \
    "$mlkem_pub_key_option:TestKeyName-ml-kem-512 $topfolder/keys/ml-kem/ml-kem-512-pubkey.$mlkem_pub_key_format --enabled-key-data key-name,encapsulation-mechanism --xml-data $topfolder/aleksey-xmlenc-01/enc-aes128gcm-em-ml-kem-512.data --node-name http://example.org/paymentv2:CreditCard" \
    "$mlkem_priv_key_option:TestKeyName-ml-kem-512 $topfolder/keys/ml-kem/ml-kem-512-key.$mlkem_priv_key_format --pwd secret123 --enabled-key-data key-name,encapsulation-mechanism"
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes192gcm-em-ml-kem-768" \
    "aes192-gcm ml-kem-768" \
    "ml-kem" \
    "$mlkem_priv_key_option:TestKeyName-ml-kem-768 $topfolder/keys/ml-kem/ml-kem-768-key.$mlkem_priv_key_format --pwd secret123 --enabled-key-data key-name,encapsulation-mechanism" \
    "$mlkem_pub_key_option:TestKeyName-ml-kem-768 $topfolder/keys/ml-kem/ml-kem-768-pubkey.$mlkem_pub_key_format --enabled-key-data key-name,encapsulation-mechanism --xml-data $topfolder/aleksey-xmlenc-01/enc-aes192gcm-em-ml-kem-768.data --node-name http://example.org/paymentv2:CreditCard" \
    "$mlkem_priv_key_option:TestKeyName-ml-kem-768 $topfolder/keys/ml-kem/ml-kem-768-key.$mlkem_priv_key_format --pwd secret123 --enabled-key-data key-name,encapsulation-mechanism"
execEncTest $res_success \
    "" \
    "aleksey-xmlenc-01/enc-aes256gcm-em-ml-kem-1024" \
    "aes256-gcm ml-kem-1024" \
    "ml-kem" \
    "$mlkem_priv_key_option:TestKeyName-ml-kem-1024 $topfolder/keys/ml-kem/ml-kem-1024-key.$mlkem_priv_key_format --pwd secret123 --enabled-key-data key-name,encapsulation-mechanism" \
    "$mlkem_pub_key_option:TestKeyName-ml-kem-1024 $topfolder/keys/ml-kem/ml-kem-1024-pubkey.$mlkem_pub_key_format --enabled-key-data key-name,encapsulation-mechanism --xml-data $topfolder/aleksey-xmlenc-01/enc-aes256gcm-em-ml-kem-1024.data --node-name http://example.org/paymentv2:CreditCard" \
    "$mlkem_priv_key_option:TestKeyName-ml-kem-1024 $topfolder/keys/ml-kem/ml-kem-1024-key.$mlkem_priv_key_format --pwd secret123 --enabled-key-data key-name,encapsulation-mechanism"
fi # xmlsec_feature_ml_kem


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
    "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --session-key aes-128 $priv_key_option:merlin-rsa-key $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --xml-data $topfolder/merlin-xmlenc-five/encrypt-element-aes128-cbc-rsa-1_5.data --node-id Purchase --pwd secret"  \
    "$priv_key_option:merlin-rsa-key $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret"

if [ "z$xmlsec_feature_rsa_oaep_sha1" = "zyes" ] ; then
    execEncTest $res_success \
        "" \
        "merlin-xmlenc-five/encrypt-data-tripledes-cbc-rsa-oaep-mgf1p" \
        "tripledes-cbc rsa-oaep-mgf1p sha1" \
        "" \
        "--lax-key-search $priv_key_option $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret" \
        "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --session-key des-192 $priv_key_option:merlin-rsa-key $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --binary-data $topfolder/merlin-xmlenc-five/encrypt-data-tripledes-cbc-rsa-oaep-mgf1p.data --pwd secret"  \
        "$priv_key_option:merlin-rsa-key $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret"
fi

if [ "z$xmlsec_feature_rsa_oaep_sha1" = "zyes" -a "z$xmlsec_feature_rsa_oaep_different_digest_and_mgf1" = "zyes" ] ; then
    execEncTest $res_success \
        "" \
        "merlin-xmlenc-five/encrypt-data-tripledes-cbc-rsa-oaep-mgf1p-sha256" \
        "tripledes-cbc rsa-oaep-mgf1p sha256 sha1" \
        "" \
        "--lax-key-search $priv_key_option $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret" \
        "--keys-file $topfolder/merlin-xmlenc-five/keys.xml --session-key des-192 $priv_key_option:merlin-rsa-key $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --binary-data $topfolder/merlin-xmlenc-five/encrypt-data-tripledes-cbc-rsa-oaep-mgf1p-sha256.data --pwd secret"  \
        "$priv_key_option:merlin-rsa-key $topfolder/merlin-xmlenc-five/rsapriv.$priv_key_format --pwd secret"
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

if [ "z$xmlsec_feature_rsa_oaep_sha1" = "zyes" ] ; then
    execEncTest $res_success \
        "" \
        "01-phaos-xmlenc-3/enc-element-3des-kt-rsa_oaep_sha1" \
        "tripledes-cbc rsa-oaep-mgf1p sha1 sha1" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
        "--session-key des-192 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-element-3des-kt-rsa_oaep_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"
fi

if [ "z$xmlsec_feature_rsa_oaep_sha1" = "zyes" -a"z$xmlsec_feature_rsa_oaep_different_digest_and_mgf1" = "zyes" ] ; then
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

if [ "z$xmlsec_feature_rsa_oaep_sha1" = "zyes" ] ; then
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
fi

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

if [ "z$xmlsec_feature_rsa_oaep_sha1" = "zyes" ] ; then
    execEncTest $res_success \
        "" \
        "01-phaos-xmlenc-3/enc-text-aes256-kt-rsa_oaep_sha1" \
        "aes256-cbc rsa-oaep-mgf1p sha1  sha1" \
        "" \
        "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret" \
        "--session-key aes-256 --keys-file $topfolder/01-phaos-xmlenc-3/keys.xml --enabled-key-data key-name,enc-key --xml-data $topfolder/01-phaos-xmlenc-3/enc-text-aes256-kt-rsa_oaep_sha1.data --node-name http://example.org/paymentv2:CreditCard"  \
        "$priv_key_option:my-rsa-key $topfolder/01-phaos-xmlenc-3/rsa-priv-key.$priv_key_format --pwd secret"
fi

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
##########################################################################
##########################################################################
echo "--- testEnc finished" >> $logfile
echo "--- testEnc finished"
if [ -z "$XMLSEC_TEST_REPRODUCIBLE" ]; then
    echo "--- detailed log is written to  $logfile"
fi
