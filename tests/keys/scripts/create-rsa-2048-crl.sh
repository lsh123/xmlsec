#!/bin/sh
#
# Creates test key
#

# load include
. "${0%/*}/include.sh"

folder="rsa"
keyname="rsa-2048"
keysize="2048"

### Revoke rsa-2048-cert and generate CRL
openssl ca -config "${openssl_conf}" -cert ca2cert.pem -keyfile ca2key.pem -gencrl -out "${folder}/${keyname}-cert-revoked-crl.pem"
openssl crl -in "${folder}/${keyname}-cert-revoked-crl.pem" -inform PEM -outform DER -out "${folder}/${keyname}-cert-revoked-crl.der"
if [ $? -ne 0 ]; then
    exit $?
fi
