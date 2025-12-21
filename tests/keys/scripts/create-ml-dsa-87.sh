#!/bin/sh
#
# Creates ml-dsa-87 key
#

# load include
. "${0%/*}/include.sh"

keyname="ml-dsa-87"
algorithm="ML-DSA-87"
genpkey_options=""

create_key_with_second_level_ca "${keyname}" "${algorithm}" "${genpkey_options}"