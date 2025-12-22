#!/bin/sh
#
# Creates test key
#

# THIS SCRIPT WORKS GREAT WITH faketime:
# faketime "2025-12-01 00:00:00" sh ./scripts/create-rsa-expired.sh
#

# load include
. "${0%/*}/include.sh"

keyname="rsa-expired"
keysize="2048"
gencert_options="-days 14"

### RSA key gen has problems with genpkey so generate keys manually
echo "*** Generating RSA key ${keyname}...."
openssl genrsa -out "${keyname}-key.pem" "${keysize}"
echo "*** Private key '${keyname}-key.pem' was created successfully"

### Create all key files from private key
create_all_key_files_from_private_key "${keyname}"

### Create certificate signed by second level CA
create_certificate_from_private_key "${keyname}" "${gencert_options}"

### Create PKCS12 file
create_pkcs12_from_private_key_and_cert "${keyname}"

openssl x509 -in "${keyname}-cert.pem" -noout -text


echo "*** UPDATE enveloping-expired-cert* veritication time! ***"

### Done
echo
echo "*** Key and certificate were created successfully: Use XMLSEC_TEST_UPDATE_XML_ON_FAILURE=yes make check-dsig to update the test files if needed."
echo

