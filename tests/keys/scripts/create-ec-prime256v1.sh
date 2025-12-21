#!/bin/sh
#
# Creates ml-dsa-44 key
#

# load include
. "${0%/*}/include.sh"

keyname="ec-prime256v1"
algorithm="EC"
genpkey_options="-pkeyopt ec_paramgen_curve:prime256v1"

create_key_with_second_level_ca "${keyname}" "${algorithm}" "${genpkey_options}"

