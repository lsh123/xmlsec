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
