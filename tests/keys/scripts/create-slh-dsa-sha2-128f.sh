#!/bin/sh
#
# Creates slh-dsa-sha2-128f key
#

# load include
. "${0%/*}/include.sh"

keyname="slh-dsa-sha2-128f"
algorithm="SLH-DSA-SHA2-128f"
genpkey_options=""

create_key_with_second_level_ca "${keyname}" "${algorithm}" "${genpkey_options}"