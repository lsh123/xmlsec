#!/bin/sh
#
# Creates ml-dsa-65 key
#

# load include
. "${0%/*}/include.sh"

folder="ml-dsa"
keyname="ml-dsa-65"
algorithm="ML-DSA-65"
genpkey_options=""

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