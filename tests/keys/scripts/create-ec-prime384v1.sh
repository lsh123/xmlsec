#!/bin/sh
#
# Creates test key
#

# load include
. "${0%/*}/include.sh"

folder="ec"
keyname="ec-prime384v1"
algorithm="EC"
genpkey_options="-pkeyopt ec_paramgen_curve:P-384"

create_key_with_second_level_ca "${keyname}" "${algorithm}" "${genpkey_options}"
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

