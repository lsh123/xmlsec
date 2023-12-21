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

# cleanup crypto config folder
mkdir -p $crypto_config_folder
rm -rf $crypto_config_folder/*

# remove old keys file
rm -rf $keysfile

##########################################################################
##########################################################################
##########################################################################
echo "--------- Positive Testing ----------"
execKeysTest $res_success   \
    "hmac"                  \
    "hmac-sha1"             \
    "test-hmac-sha1"        \
    "hmac-192"

execKeysTest $res_success       \
    "rsa"                       \
    "rsa-sha256 sha256"         \
    "test-rsa"                  \
    "rsa-2048"                  \
    "$topfolder/keys/largersakey$priv_key_suffix"  \
    "$topfolder/keys/largersapubkey" \
    "$topfolder/keys/largersacert"   \
    "$topfolder/aleksey-xmldsig-01/enveloped-sha256-rsa-sha256" \
    "--pwd secret123 --enabled-key-data key-name"

execKeysTest $res_success       \
    "dsa"                       \
    "dsa-sha256 sha256"         \
    "test-dsa"                  \
    "dsa-1024"                  \
    "$topfolder/keys/dsa2048key"    \
    "$topfolder/keys/dsa2048pubkey" \
    "$topfolder/keys/dsa2048cert"   \
    "$topfolder/aleksey-xmldsig-01/enveloped-sha256-dsa2048-sha256" \
    "--pwd secret123 --enabled-key-data key-name"

execKeysTest $res_success   \
    "ec"                    \
    "ecdsa-sha256 sha256"   \
    ""                      \
    "ec"                    \
    "$topfolder/keys/ecdsa-secp256r1-key" \
    "$topfolder/keys/ecdsa-secp256r1-pubkey" \
    "$topfolder/keys/ecdsa-secp256r1-cert" \
    "$topfolder/aleksey-xmldsig-01/enveloped-sha256-ecdsa-sha256" \
    "--pwd secret123 --enabled-key-data key-name"

# generating large dh keys takes forever
execKeysTest $res_success   \
    "dh"                    \
    ""                      \
    ""                      \
    "dh"

execKeysTest $res_success   \
    "des"                   \
    ""                      \
    "test-des"              \
    "des-192"

execKeysTest $res_success   \
    "aes"                   \
    ""                      \
    "test-aes128"           \
    "aes-128"

execKeysTest $res_success   \
    "aes"                   \
    ""                      \
    "test-aes192"           \
    "aes-192"

execKeysTest $res_success   \
    "aes"                   \
    ""                      \
    "test-aes256"           \
    "aes-256"

##########################################################################
##########################################################################
##########################################################################
echo "--- testKeys finished ---" >> $logfile
echo "--- testKeys finished ---"
if [ -z "$XMLSEC_TEST_REPRODUCIBLE" ]; then
    echo "--- detailed log is written to  $logfile ---"
fi
