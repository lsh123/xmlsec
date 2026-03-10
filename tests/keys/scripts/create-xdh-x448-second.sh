#!/bin/sh
#
# Creates test key
#

# load include
. "${0%/*}/include.sh"

folder="xdh"
keyname="xdh-x448-second"
algorithm="X448"


echo "*** Generating ${algorithm} key ${keyname}...."
openssl genpkey -algorithm ${algorithm} -out "${keyname}-key.pem"
if [ $? -ne 0 ]; then
    echo "Error: Failed to create private key"
    exit $?
fi
echo "*** Private key '${keyname}-key.pem' was created successfully"

### Create all key files from private key
create_all_key_files_from_private_key "${keyname}"
if [ $? -ne 0 ]; then
    exit $?
fi

### Create certificate signed by second level CA
create_certificate_from_private_key "${keyname}" ""
if [ $? -ne 0 ]; then
    exit $?
fi

### Create PKCS12 file
create_pkcs12_from_private_key_and_cert "${keyname}"
if [ $? -ne 0 ]; then
    exit $?
fi

# move to the right place
mv ${keyname}* "${folder}/"
if [ $? -ne 0 ]; then
    exit $?
fi

### Done
echo
echo "*** X448 key and certificate files were created successfully and moved to '${folder}' folder."
echo
