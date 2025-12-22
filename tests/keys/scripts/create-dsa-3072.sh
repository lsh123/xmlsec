#!/bin/sh
#
# Creates test key
#

# load include
. "${0%/*}/include.sh"

keyname="dsa-3072"
algorithm="DSA"
genpkey_options="-pkeyopt dsa_paramgen_bits:3072 -pkeyopt dsa_paramgen_q_bits:256"

create_key_with_second_level_ca "${keyname}" "${algorithm}" "${genpkey_options}"
