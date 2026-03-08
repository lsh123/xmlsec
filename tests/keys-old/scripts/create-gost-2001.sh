#!/bin/sh
#
# Creates test key
#

# load include
. "${0%/*}/include.sh"

folder="gost"
keyname="gost-2001"
algorithm="gost2001"
genpkey_options="-pkeyopt paramset:A"

openssl genpkey -algorithm "${algorithm}" ${genpkey_options} -out "${keyname}-key.pem"

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
mv ${keyname}* "${folder}/"
if [ $? -ne 0 ]; then
    exit $?
fi

### Done
echo
echo "*** Key and certificate were created successfully and moved to '${folder}' folder"
echo

