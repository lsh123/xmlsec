#!/bin/sh
#
# Creates ml-dsa-44 key
#

# load include
. "${0%/*}/include.sh"

keyname="dsa-2048"
algorithm="DSA"
genpkey_options="-pkeyopt dsa_paramgen_bits:2048 -pkeyopt dsa_paramgen_q_bits:256"

create_key_with_second_level_ca "${keyname}" "${algorithm}" "${genpkey_options}"
