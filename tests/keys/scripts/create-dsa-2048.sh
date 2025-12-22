#!/bin/sh
#
# Creates test key
#

# load include
. "${0%/*}/include.sh"

folder="dsa"
keyname="dsa-2048"
algorithm="DSA"
genpkey_options="-pkeyopt dsa_paramgen_bits:2048 -pkeyopt dsa_paramgen_q_bits:256"

create_key_with_second_level_ca "${keyname}" "${algorithm}" "${genpkey_options}"
if [ $? -ne 0 ]; then
    exit $?
fi

# move to the right place
mv "${keyname}*" "${folder}/"
if [ $? -ne 0 ]; then
exit $?
fi

### Done
echo
echo "*** Key and certificate were created successfully and moved to '${folder}' folder"
echo
