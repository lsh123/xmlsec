#!/bin/sh
#
# Creates ml-dsa-87 key
#

# load include
. "${0%/*}/include.sh"

algorithm="ML-DSA-87"
keyname="ml-dsa-87"
subject="/C=US/ST=California/O=XML Security Library \(http:\/\/www.aleksey.com\/xmlsec\)/CN=${algorithm} Key"

create_key_with_second_level_ca "${algorithm}" "${keyname}" "${subject}"