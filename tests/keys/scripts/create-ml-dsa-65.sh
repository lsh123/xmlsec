#!/bin/sh
#
# Creates ml-dsa-65 key
#

# load include
. "${0%/*}/include.sh"

algorithm="ML-DSA-65"
keyname="ml-dsa-65"
subject="/C=US/ST=California/O=XML Security Library \(http:\/\/www.aleksey.com\/xmlsec\)/CN=${algorithm} Key"

create_key_with_second_level_ca "${algorithm}" "${keyname}" "${subject}"