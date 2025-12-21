#!/bin/sh
#
# Creates test key
#

# load include
. "${0%/*}/include.sh"

keyname="ml-dsa-44"
algorithm="ML-DSA-44"
genpkey_options=""

create_key_with_second_level_ca "${keyname}" "${algorithm}" "${genpkey_options}"
