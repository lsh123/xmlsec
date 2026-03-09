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

### Create public key from private key
create_public_key_from_private_key "${keyname}"
if [ $? -ne 0 ]; then
    exit $?
fi

### Create DER files
create_der_keys_from_private_and_public_key "${keyname}"
if [ $? -ne 0 ]; then
    exit $?
fi

### Create PKCS8 files
create_pkcs8_keys_from_private_key "${keyname}"
if [ $? -ne 0 ]; then
    exit $?
fi

# Note: XDH keys cannot be used for signing, so we skip certificate and PKCS12 generation

# move to the right place
mv ${keyname}* "${folder}/"
if [ $? -ne 0 ]; then
    exit $?
fi

### Done
echo
echo "*** X448 key files were created successfully and moved to '${folder}' folder."
echo "*** Note: XDH keys are for key agreement only, certificates were not generated."
echo
