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

if [ "z$OS_ARCH" = "zCygwin" ] ; then
    topfolder=`cygpath -wa "$topfolder"`
    xmlsec_app=`cygpath -a "$xmlsec_app"`
fi

#
# Prepare folders
#
if [ "z$TMPFOLDER" = "z" ] ; then
    TMPFOLDER=/tmp
fi
testname=`basename $testfile`
if [ "z$OS_ARCH" = "zCygwin" ] ; then
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
nssdbfolder=$topfolder/nssdb

#
# Valgrind
#
valgrind_suppression="--suppressions=$topfolder/openssl.supp --suppressions=$topfolder/nss.supp"
valgrind_options="--leak-check=yes --show-reachable=yes --num-callers=32 -v"
if [ -n "$DEBUG_MEMORY" ] ; then 
    export VALGRIND="valgrind $valgrind_options"
    export REPEAT=3
    xmlsec_params="$xmlsec_params --repeat $REPEAT"
fi

#
# Setup crypto engine
#
crypto_config=$TMPFOLDER/xmlsec-crypto-config
keysfile=$crypto_config/keys.xml
if [ "z$XMLSEC_DEFAULT_CRYPTO" != "z" ] ; then
    xmlsec_params="$xmlsec_params --crypto $XMLSEC_DEFAULT_CRYPTO"
elif [ "z$crypto" != "z" ] ; then
    xmlsec_params="$xmlsec_params --crypto $crypto"
fi
xmlsec_params="$xmlsec_params --crypto-config $crypto_config"

#
# Setup keys config
#
pub_key_format=$file_format
cert_format=$file_format

#
# GCrypt/GnuTLS only supports DER format for now, others are good to go with PKCS12
#
if [ "z$crypto" != "zgcrypt" ] ; then
    priv_key_option="--pkcs12"
    priv_key_format="p12"
else
    priv_key_option="--privkey-der"
    priv_key_format="der"
    pub_key_format="der"
fi

#
# Need to force persistence for mscrypto and mscng
#
if [ "z$crypto" = "zmscrypto" -o "z$crypto" = "zmscng" ] ; then
    priv_key_option="--pkcs12-persist $priv_key_option"
fi

# On Windows, one needs to specify Crypto Service Provider (CSP)
# in the pkcs12 file to ensure it is loaded correctly to be used
# with SHA2 algorithms. Worse, the CSP is different for XP and older 
# versions
if test "z$OS_ARCH" = "zCygwin" || test "z$OS_ARCH" = "zMsys" ; then
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

NSS_TEST_CERT_NICKNAME="NSS Certificate DB:Aleksey Sanin - XML Security Library (http://www.aleksey.com/xmlsec)"


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
    if [ $actual_res = 0 ]; then
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
    if [ $check_res = 0 ]; then
        echo "   OK"
    else
	count_skip=`expr $count_skip + 1`
        echo " Skip"
    fi
    return "$check_res"
}

#
# Keys Manager test function
#
execKeysTest() {
    expected_res="$1"
    req_key_data="$2"
    key_name="$3"
    alg_name="$4"
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
    echo "Test: $alg_name ($expected_res)"
    echo "Test: $alg_name ($expected_res)" > $curlogfile

    # check key data
    if [ -n "$req_key_data" ] ; then
        printf "    Checking required key data                            "
        echo "$xmlsec_app check-key-data $xmlsec_params $req_key_data" >> $curlogfile
        $xmlsec_app check-key-data $xmlsec_params $req_key_data >> $curlogfile 2>> $curlogfile
        printCheckStatus $?
        res=$?
        if [ $res != 0 ]; then
	    cat $curlogfile >> $logfile
	    cd $old_pwd
            return
        fi
    fi

    # run tests
    printf "    Creating new key                                      "
    params="--gen-key:$key_name $alg_name"
    if [ -f $keysfile ] ; then
        params="$params --keys-file $keysfile"
    fi
    echo "$VALGRIND $xmlsec_app keys $params $xmlsec_params $keysfile" >>  $curlogfile 
    $VALGRIND $xmlsec_app keys $params $xmlsec_params $keysfile >> $curlogfile 2>> $curlogfile
    printRes $expected_res $?
    if [ $? != 0 ]; then
        failures=`expr $failures + 1`
    fi

    # save logs
    cat $curlogfile >> $logfile
    if [ $failures != 0 ] ; then
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
        echo $folder/$filename
        echo "Test: $folder/$filename in folder " `pwd` " ($expected_res)" > $curlogfile
    else
        full_file=$topfolder/$filename
        echo $filename
        echo "Test: $folder/$filename ($expected_res)" > $curlogfile
    fi

    # check transforms
    if [ -n "$req_transforms" ] ; then
        printf "    Checking required transforms                         "
        echo "$xmlsec_app check-transforms $xmlsec_params $req_transforms" >> $curlogfile
        $xmlsec_app check-transforms $xmlsec_params $req_transforms >> $curlogfile 2>> $curlogfile
        printCheckStatus $?
        res=$?
        if [ $res != 0 ]; then
            cat $curlogfile >> $logfile
	    cd $old_pwd
            return
        fi
    fi

    # check key data
    if [ -n "$req_key_data" ] ; then
        printf "    Checking required key data                           "
        echo "$xmlsec_app check-key-data $xmlsec_params $req_key_data" >> $curlogfile
        $xmlsec_app check-key-data $xmlsec_params $req_key_data >> $curlogfile 2>> $curlogfile
        printCheckStatus $?
        res=$?
        if [ $res != 0 ]; then
            cat $curlogfile >> $logfile
	    cd $old_pwd
            return
        fi
    fi

    # run tests
    if [ -n "$params1" ] ; then
        printf "    Verify existing signature                            "
        echo "$VALGRIND $xmlsec_app verify --X509-skip-strict-checks $xmlsec_params $params1 $full_file.xml" >> $curlogfile
        $VALGRIND $xmlsec_app verify --X509-skip-strict-checks $xmlsec_params $params1 $full_file.xml >> $curlogfile 2>> $curlogfile
        printRes $expected_res $?
        if [ $? != 0 ]; then
            failures=`expr $failures + 1`
        fi
    fi

    if [ -n "$params2" -a -z "$PERF_TEST" ] ; then
        printf "    Create new signature                                 "
        echo "$VALGRIND $xmlsec_app sign $xmlsec_params $params2 --output $tmpfile $full_file.tmpl" >> $curlogfile
        $VALGRIND $xmlsec_app sign $xmlsec_params $params2 --output $tmpfile $full_file.tmpl >> $curlogfile 2>> $curlogfile
        printRes $res_success $?
        if [ $? != 0 ]; then
            failures=`expr $failures + 1`
        fi
    fi

    if [ -n "$params3" -a -z "$PERF_TEST" ] ; then
        printf "    Verify new signature                                 "
        echo "$VALGRIND $xmlsec_app verify --X509-skip-strict-checks $xmlsec_params $params3 $tmpfile" >> $curlogfile
        $VALGRIND $xmlsec_app verify --X509-skip-strict-checks $xmlsec_params $params3 $tmpfile >> $curlogfile 2>> $curlogfile
        printRes $res_success $?
        if [ $? != 0 ]; then
            failures=`expr $failures + 1`
        fi
    fi

    # save logs
    cat $curlogfile >> $logfile
    if [ $failures != 0 ] ; then
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
    params1="$5"
    params2="$6"
    params3="$7"
    outputTransform="$8"
    failures=0

    if [ -n "$XMLSEC_TEST_NAME" -a "$XMLSEC_TEST_NAME" != "$filename" ]; then
        return
    fi

    # prepare
    rm -f $tmpfile $tmpfile.2
    old_pwd=`pwd`

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
        echo $folder/$filename
        echo "Test: $folder/$filename in folder " `pwd` " ($expected_res)" > $curlogfile
    else
        full_file=$topfolder/$filename
        echo $filename
        echo "Test: $folder/$filename ($expected_res)" > $curlogfile
    fi

    # check transforms
    if [ -n "$req_transforms" ] ; then
        printf "    Checking required transforms                         "
        echo "$xmlsec_app check-transforms $xmlsec_params $req_transforms" >> $curlogfile
        $xmlsec_app check-transforms $xmlsec_params $req_transforms >> $curlogfile 2>> $curlogfile
        printCheckStatus $?
        res=$?
        if [ $res != 0 ]; then
	    cat $curlogfile >> $logfile
	    cd $old_pwd
            return
        fi
    fi

    # run tests
    if [ -n "$params1" ] ; then
        rm -f $tmpfile
        printf "    Decrypt existing document                            "
        echo "$VALGRIND $xmlsec_app decrypt $xmlsec_params $params1 $full_file.xml" >>  $curlogfile
        $VALGRIND $xmlsec_app decrypt $xmlsec_params $params1 --output $tmpfile $full_file.xml >> $curlogfile  2>> $curlogfile
        res=$?
        echo "=== TEST RESULT: $res; expected: $expected_res" >> $curlogfile
        if [ $res = 0 -a "$expected_res" = "$res_success" ]; then
            if [ "z$outputTransform" != "z" ] ; then
                cat $tmpfile | $outputTransform > $tmpfile.2
                mv $tmpfile.2 $tmpfile
            fi
            diff $diff_param $full_file.data $tmpfile >> $curlogfile 2>> $curlogfile
            printRes $expected_res $?
        else
            printRes $expected_res $res
        fi
    	if [ $? != 0 ]; then
            failures=`expr $failures + 1`
    	fi
    fi

    if [ -n "$params2" -a -z "$PERF_TEST" ] ; then
        rm -f $tmpfile
        printf "    Encrypt document                                     "
        echo "$VALGRIND $xmlsec_app encrypt $xmlsec_params $params2 --output $tmpfile $full_file.tmpl" >>  $curlogfile 
        $VALGRIND $xmlsec_app encrypt $xmlsec_params $params2 --output $tmpfile $full_file.tmpl >> $curlogfile 2>> $curlogfile
        printRes $res_success $?
        if [ $? != 0 ]; then
            failures=`expr $failures + 1`
        fi
    fi

    if [ -n "$params3" -a -z "$PERF_TEST" ] ; then 
        rm -f $tmpfile.2
        printf "    Decrypt new document                                 "
        echo "$VALGRIND $xmlsec_app decrypt $xmlsec_params $params3 --output $tmpfile.2 $tmpfile" >>  $curlogfile
        $VALGRIND $xmlsec_app decrypt $xmlsec_params $params3 --output $tmpfile.2 $tmpfile >> $curlogfile 2>> $curlogfile
        res=$?
        if [ $res = 0 ]; then
            if [ "z$outputTransform" != "z" ] ; then
                cat $tmpfile.2 | $outputTransform > $tmpfile
                mv $tmpfile $tmpfile.2
            fi
            diff $diff_param $full_file.data $tmpfile.2 >> $curlogfile 2>> $curlogfile
            printRes $res_success $?
        else
            printRes $res_success $res
        fi
        if [ $? != 0 ]; then
            failures=`expr $failures + 1`
        fi
    fi

    # save logs
    cat $curlogfile >> $logfile
    if [ $failures != 0 ] ; then
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

# print results
echo "--- TOTAL OK: $count_success; TOTAL FAILED: $count_fail; TOTAL SKIPPED: $count_skip" >> $logfile
echo "--- TOTAL OK: $count_success; TOTAL FAILED: $count_fail; TOTAL SKIPPED: $count_skip"

# print log file if failed
if [ $count_fail != 0 ] ; then
    cat $failedlogfile
fi

# cleanup
rm -rf $tmpfile $tmpfile.2 tmpfile.3 $curlogfile

exit $count_fail

