#!/bin/sh
#
# Creates test key
#

# load include
. "${0%/*}/include.sh"

keyname="dhx-rfc5114-3-first"
algorithm="DHX"
genpkey_options="-pkeyopt dh_rfc5114:3"

create_key "${keyname}" "${algorithm}" "${genpkey_options}"
