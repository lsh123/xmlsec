#!/bin/sh
#
# Creates slh-dsa-sha2-128f key
#

# load include
. "${0%/*}/include.sh"

algorithm="SLH-DSA-SHA2-128f"
keyname="slh-dsa-sha2-128f"
subject="/C=US/ST=California/O=XML Security Library \(http:\/\/www.aleksey.com\/xmlsec\)/CN=${algorithm} Key"

create_key_with_second_level_ca "${algorithm}" "${keyname}" "${subject}"
