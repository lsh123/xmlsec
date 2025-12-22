#!/bin/sh
#
# Creates test key
#

# load include
. "${0%/*}/include.sh"

keyname="rsa-2048"
keysize="2048"


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

### Revoke rsa-2048-cert and generate CRL
openssl ca -config "${openssl_conf}" -cert ca2cert.pem -keyfile ca2key.pem -revoke "${keyname}-cert.pem"
openssl ca -config "${openssl_conf}" -cert ca2cert.pem -keyfile ca2key.pem -gencrl -out "${keyname}-cert-revoked-crl.pem"
openssl crl -in "${keyname}-cert-revoked-crl.pem" -inform PEM -outform DER -out "${keyname}-cert-revoked-crl.der"


### Done
echo
echo "*** Key and certificate were created successfully: Use XMLSEC_TEST_UPDATE_XML_ON_FAILURE=yes make check-dsig to update the test files if needed."
echo

