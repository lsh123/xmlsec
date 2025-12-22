#!/bin/sh
#
# Creates test key
#

# load include
. "${0%/*}/include.sh"

keyname="dsa-1024"
algorithm="DSA"
genpkey_options="-pkeyopt dsa_paramgen_bits:1024 -pkeyopt dsa_paramgen_q_bits:160"

create_key_with_second_level_ca "${keyname}" "${algorithm}" "${genpkey_options}"

echo "*** MANUAL UPDATE REQUIRED: put the ceritiificate from 'dsa-1024-cert.pem' in the 'merlin-xmldsig-twenty-three/signature.tmpl' file"
