#!/bin/sh 
#
# This script needs to be called from testrun.sh script
#

##########################################################################
##########################################################################
##########################################################################
echo "--- testXKMS started for xmlsec-$crypto library ($timestamp)" 
echo "--- LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
echo "--- log file is $logfile"
echo "--- testXKMS started for xmlsec-$crypto library ($timestamp)" >> $logfile
echo "--- LD_LIBRARY_PATH=$LD_LIBRARY_PATH" >> $logfile

##########################################################################
##########################################################################
##########################################################################
echo "--------- Positive Testing ----------"

execXkmsServerRequestTest $res_success \
    "" \
    "aleksey-xkms-01/locate-example-1" \
    "" \
    "no-match" \
    "--xkms-service http://www.example.com/xkms"

execXkmsServerRequestTest $res_success \
    "" \
    "aleksey-xkms-01/locate-example-1" \
    "" \
    "bad-service" \
    "--xkms-service http://www.example.com/xkms-bad-service"

execXkmsServerRequestTest $res_success \
    "" \
    "aleksey-xkms-01/locate-example-2" \
    "" \
    "no-match" \
    "--xkms-service http://www.example.com/xkms"

execXkmsServerRequestTest $res_success \
    "" \
    "aleksey-xkms-01/validate-example-1" \
    "" \
    "no-match" \
    "--xkms-service http://www.example.com/xkms"

execXkmsServerRequestTest $res_success \
    "" \
    "aleksey-xkms-01/locate-opaque-client-data" \
    "" \
    "no-match" \
    "--xkms-service http://www.example.com/xkms"

execXkmsServerRequestTest $res_success \
    "" \
    "aleksey-xkms-01/compound-example-1" \
    "" \
    "no-match" \
    "--xkms-service http://www.example.com/xkms"

execXkmsServerRequestTest $res_success \
    "" \
    "aleksey-xkms-01/status-request" \
    "" \
    "success" \
    "--xkms-service http://www.example.com/xkms"

execXkmsServerRequestTest $res_success \
    "" \
    "aleksey-xkms-01/bad-request-name" \
    "" \
    "not-supported" \
    "--xkms-service http://www.example.com/xkms"

execXkmsServerRequestTest $res_success \
    "" \
    "aleksey-xkms-01/soap12-locate-example-1" \
    "" \
    "no-match" \
    "--xkms-service http://www.example.com/xkms --xkms-format soap-1.2"

execXkmsServerRequestTest $res_success \
    "" \
    "aleksey-xkms-01/soap11-locate-example-1" \
    "" \
    "unsupported" \
    "--xkms-service http://www.example.com/xkms --xkms-format soap-1.2"

execXkmsServerRequestTest $res_success \
    "" \
    "aleksey-xkms-01/soap12-bad-request-name" \
    "" \
    "msg-invalid" \
    "--xkms-service http://www.example.com/xkms --xkms-format soap-1.2"

execXkmsServerRequestTest $res_success \
    "" \
    "aleksey-xkms-01/soap11-locate-example-1" \
    "" \
    "no-match" \
    "--xkms-service http://www.example.com/xkms --xkms-format soap-1.1"

execXkmsServerRequestTest $res_success \
    "" \
    "aleksey-xkms-01/soap12-locate-example-1" \
    "" \
    "unsupported" \
    "--xkms-service http://www.example.com/xkms --xkms-format soap-1.1"

execXkmsServerRequestTest $res_success \
    "" \
    "aleksey-xkms-01/soap11-bad-request-name" \
    "" \
    "msg-invalid" \
    "--xkms-service http://www.example.com/xkms --xkms-format soap-1.1"

##########################################################################
##########################################################################
##########################################################################
echo "--------- Negative Testing ----------"

##########################################################################
##########################################################################
##########################################################################
echo "--- testXKMS finished" >> $logfile
echo "--- testXKMS finished"
echo "--- detailed log is written to  $logfile" 

