#!/bin/sh
#
# Creates test key
#

# load include
. "${0%/*}/include.sh"

folder="dsa"
keyname="dsa-1024"
algorithm="DSA"
genpkey_options="-pkeyopt dsa_paramgen_bits:1024 -pkeyopt dsa_paramgen_q_bits:160"

create_key_with_second_level_ca "${keyname}" "${algorithm}" "${genpkey_options}"
if [ $? -ne 0 ]; then
    exit $?
fi

echo "*** MANUAL UPDATE REQUIRED: put the ceritiificate from 'dsa-1024-cert.pem' in the 'merlin-xmldsig-twenty-three/signature.tmpl' file"

# move to the right place
mv "${keyname}*" "${folder}/"
if [ $? -ne 0 ]; then
exit $?
fi

### Done
echo
echo "*** Key and certificate were created successfully and moved to '${folder}' folder"
echo
