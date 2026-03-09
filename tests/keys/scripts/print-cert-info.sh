#!/bin/sh
#
# Creates test key
#

# load include
. "${0%/*}/include.sh"
filename="${1}"

echo "** Validity: ***"
openssl x509 -in "${filename}" -noout -text | grep "Not Before\|Not After" | sed 's/^ *//'
echo

echo "** Subject Name: ***"
openssl x509 -in "${filename}" -noout -text | grep "Subject:" | sed 's/.*Subject: //'
echo

echo "** Issuer Name: ***"
openssl x509 -in "${filename}" -noout -text | grep "Issuer:" | sed 's/.*Issuer: //'
echo

echo "** Issuer Serial: ***"
openssl x509 -noout -serial -in "${filename}" | cut -d'=' -f2 | tr -d '\n' | xargs -I {} echo "ibase=16; {}" | bc
echo

echo "** SKI: ***"
openssl x509 -in "${filename}" -noout -ext subjectKeyIdentifier | tail -1 | xxd -r -p | openssl base64
echo

echo "** Digest( SHA1 ): ***"
openssl x509 -in "${filename}" -noout -fingerprint -sha1 | cut -d'=' -f2 | xxd -r -p | openssl base64
echo

echo "** Digest( SHA224 ): ***"
openssl x509 -in "${filename}" -noout -fingerprint -sha224 | cut -d'=' -f2 | xxd -r -p | openssl base64
echo

echo "** Digest( SHA256 ): ***"
openssl x509 -in "${filename}" -noout -fingerprint -sha256 | cut -d'=' -f2 | xxd -r -p | openssl base64
echo

echo "** Digest( SHA384 ): ***"
openssl x509 -in "${filename}" -noout -fingerprint -sha384 | cut -d'=' -f2 | xxd -r -p | openssl base64
echo

echo "** Digest( SHA512 ): ***"
openssl x509 -in "${filename}" -noout -fingerprint -sha512 | cut -d'=' -f2 | xxd -r -p | openssl base64
echo

echo "** Digest( SHA3-224 ): ***"
openssl x509 -in "${filename}" -noout -fingerprint -sha3-224 | cut -d'=' -f2 | xxd -r -p | openssl base64
echo

echo "** Digest( SHA3-256 ): ***"
openssl x509 -in "${filename}" -noout -fingerprint -sha3-256 | cut -d'=' -f2 | xxd -r -p | openssl base64
echo

echo "** Digest( SHA3-384 ): ***"
openssl x509 -in "${filename}" -noout -fingerprint -sha3-384 | cut -d'=' -f2 | xxd -r -p | openssl base64
echo

echo "** Digest( SHA3-512 ): ***"
openssl x509 -in "${filename}" -noout -fingerprint -sha3-512 | cut -d'=' -f2 | xxd -r -p | openssl base64
echo


echo "NOTE: NSS is very particular about the order of DN fields, make sure to tests nss to confirm subject/issuer names work as expected."
