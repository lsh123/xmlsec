#!/bin/sh
# Test --add-key-value flag (OpenSSL only)

# ensure this script is called from testrun.sh
if [ -z "$xmlsec_app" -o -z "$xmlsec_params" ]; then
    echo "This script needs to be called from testrun.sh script"
    exit 1
fi

# exit early if the current crypto backend is not OpenSSL
if [ "$crypto" != "openssl" ]; then
    printf -- "--- Skip testAddKeyValue (backend: %s) ---           " "$crypto"
    printCheckStatus 1
    exit 0
fi

if [ -z "$XMLSEC_TEST_REPRODUCIBLE" ]; then
    echo "--- testAddKeyValue started for xmlsec-$crypto library ($timestamp) ---"
fi

setupTest

printf "    Sign with --add-key-value                             "
cmd="$VALGRIND $xmlsec_app sign $xmlsec_params --add-key-value --lax-key-search  $priv_key_option  $topfolder/keys/rsakey$priv_key_suffix.$priv_key_format --pwd secret123 --enabled-key-data rsa,x509 --output $tmpfile $topfolder/aleksey-xmldsig-01/enveloping-sha256-rsa-sha256-addkeyvalue.tmpl"
echo "$cmd" >> $curlogfile
$cmd >> $curlogfile 2>> $curlogfile
printRes $res_success $?
if [ $? -ne 0 ]; then
    tearDownTest
    exit 0
fi

printf "    Check <KeyValue> presence                             "
python3 - "$tmpfile" <<'PY' > /dev/null
import sys, xml.etree.ElementTree as ET
ns={'ds':'http://www.w3.org/2000/09/xmldsig#'}
root=ET.parse(sys.argv[1]).getroot()
mod=root.find('.//ds:KeyValue/ds:RSAKeyValue/ds:Modulus', ns)
exp=root.find('.//ds:KeyValue/ds:RSAKeyValue/ds:Exponent', ns)
if mod is None or not mod.text or exp is None or not exp.text:
    sys.exit(1)
sys.exit(0)
PY
printRes $res_success $?

printf "    Verify new signature                                  "
cmd="$VALGRIND $xmlsec_app verify --lax-key-search --X509-skip-strict-checks $xmlsec_params --crypto-config $default_crypto_config --pubkey-pem $topfolder/keys/rsakey-pub.pem --enabled-key-data rsa,x509 $tmpfile"
echo "$cmd" >> $curlogfile
$cmd >> $curlogfile 2>> $curlogfile
printRes $res_success $?

tearDownTest