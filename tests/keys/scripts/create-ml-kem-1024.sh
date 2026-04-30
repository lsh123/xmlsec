#!/bin/sh
#
# Creates test key
#

# load include
. "${0%/*}/include.sh"

folder="ml-kem"
keyname="ml-kem-1024"
algorithm="ML-KEM-1024"

echo
echo "*** Generating ${algorithm} key ${keyname}...."
echo
openssl genpkey -algorithm ${algorithm} -out "${keyname}-key.pem"
if [ $? -ne 0 ]; then
    exit $?
fi
echo "*** Private key '${keyname}-key.pem' was created successfully"

### Create all key files from private key
create_all_key_files_from_private_key "${keyname}"
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
echo "*** Key was created successfully and moved to '${folder}' folder."
echo
