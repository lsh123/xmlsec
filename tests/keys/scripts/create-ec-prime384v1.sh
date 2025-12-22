#!/bin/sh
#
# Creates test key
#

# load include
. "${0%/*}/include.sh"

keyname="ec-prime384v1"
algorithm="EC"
genpkey_options="-pkeyopt ec_paramgen_curve:P-384"

create_key_with_second_level_ca "${keyname}" "${algorithm}" "${genpkey_options}"

