#!/bin/sh
#
# Creates test key
#

# load include
. "${0%/*}/include.sh"

folder="slh-dsa"
keyname="slh-dsa-sha2-192s"
algorithm="SLH-DSA-SHA2-192s"
genpkey_options=""
gencert_options=""


echo "*** Generating ${algorithm} key ${keyname}...."
openssl genpkey -algorithm  ${algorithm} ${genpkey_options} -out "${keyname}-key.pem"
echo "*** Private key '${keyname}-key.pem' was created successfully"
if [ $? -ne 0 ]; then
    exit $?
fi

### Create all key files from private key
create_all_key_files_from_private_key "${keyname}"
if [ $? -ne 0 ]; then
    exit $?
fi

### Create certificate signed by second level CA
create_certificate_from_private_key "${keyname}" "${gencert_options}"
if [ $? -ne 0 ]; then
    exit $?
fi

### Create PKCS12 file
create_pkcs12_from_private_key_and_cert "${keyname}"
if [ $? -ne 0 ]; then
    exit $?
fi

# move to the right place
mv "${keyname}"* "${folder}/"
if [ $? -ne 0 ]; then
exit $?
fi

### Done
echo
echo "*** Key and certificate were created successfully and moved to '${folder}' folder: Use XMLSEC_TEST_UPDATE_XML_ON_FAILURE=yes make check-dsig to update the test files if needed."
echo
