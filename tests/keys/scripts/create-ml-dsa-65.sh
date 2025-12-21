#!/bin/sh
#
# Creates ml-dsa-65 key
#

# load include
. "${0%/*}/include.sh"

keyname="ml-dsa-65"
algorithm="ML-DSA-65"
genpkey_options=""

create_key_with_second_level_ca "${keyname}" "${algorithm}" "${genpkey_options}"