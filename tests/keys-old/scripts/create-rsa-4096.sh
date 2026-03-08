#!/bin/sh
#
# Creates test key
#

# load include
. "${0%/*}/include.sh"

folder="rsa"
keyname="rsa-4096"
keysize="4096"


### RSA key gen has problems with genpkey so generate keys manually
echo "*** Generating RSA key ${keyname}...."
openssl genrsa -out "${keyname}-key.pem" "${keysize}"
echo "*** Private key '${keyname}-key.pem' was created successfully"

### Create all key files from private key
create_all_key_files_from_private_key "${keyname}"

### Some libraries (e.g GCrypt) don't like the newer versions of DER formats. So we use
### old (traditional, ASN1, etc) formats instead
openssl rsa -inform PEM -outform DER -traditional -pubin -RSAPublicKey_out -in ${keyname}-pubkey.pem -out ${keyname}-pubkey-gcrypt.der


### Create certificate signed by second level CA
create_certificate_from_private_key "${keyname}" "${gencert_options}"

### Create PKCS12 file
create_pkcs12_from_private_key_and_cert "${keyname}"

# Print cert info
echo "*** Certificate info: update tests accordingly in: ***"
echo "      tests/xmldsig11-interop-2012/signature-enveloping-x509digest-rsa.tmpl"
echo "      tests/aleksey-xmldsig-01/enveloped-x509-*.tmpl"
echo "      tests/aleksey-xmlenc-01/enc_rsa_1_5_x509_*.tmpl"

openssl x509 -in "${keyname}-cert.pem" -noout -text

echo "** Issuer Serial: ***"
openssl x509 -noout -serial -in "${keyname}-cert.pem" | cut -d'=' -f2 | tr -d '\n' | xargs -I {} printf "%u\n" "0x{}"

echo "** SKI: ***"
openssl x509 -in "${keyname}-cert.pem" -noout -ext subjectKeyIdentifier | tail -1 | xxd -r -p | openssl base64

echo "** Digest( SHA1 ): ***"
openssl x509 -in "${keyname}-cert.pem" -noout -fingerprint -sha1 | cut -d'=' -f2 | xxd -r -p | openssl base64

echo "** Digest( SHA224 ): ***"
openssl x509 -in "${keyname}-cert.pem" -noout -fingerprint -sha224 | cut -d'=' -f2 | xxd -r -p | openssl base64

echo "** Digest( SHA256 ): ***"
openssl x509 -in "${keyname}-cert.pem" -noout -fingerprint -sha256 | cut -d'=' -f2 | xxd -r -p | openssl base64

echo "** Digest( SHA384 ): ***"
openssl x509 -in "${keyname}-cert.pem" -noout -fingerprint -sha384 | cut -d'=' -f2 | xxd -r -p | openssl base64

echo "** Digest( SHA512 ): ***"
openssl x509 -in "${keyname}-cert.pem" -noout -fingerprint -sha512 | cut -d'=' -f2 | xxd -r -p | openssl base64

echo "** Digest( SHA3-224 ): ***"
openssl x509 -in "${keyname}-cert.pem" -noout -fingerprint -sha3-224 | cut -d'=' -f2 | xxd -r -p | openssl base64

echo "** Digest( SHA3-256 ): ***"
openssl x509 -in "${keyname}-cert.pem" -noout -fingerprint -sha3-256 | cut -d'=' -f2 | xxd -r -p | openssl base64

echo "** Digest( SHA3-384 ): ***"
openssl x509 -in "${keyname}-cert.pem" -noout -fingerprint -sha3-384 | cut -d'=' -f2 | xxd -r -p | openssl base64

echo "** Digest( SHA3-512 ): ***"
openssl x509 -in "${keyname}-cert.pem" -noout -fingerprint -sha3-512 | cut -d'=' -f2 | xxd -r -p | openssl base64


echo "NOTE: NSS is very particular about the order of DN fields, make sure to tests nss to confirm subject/issuer names work as expected."


# move to the right place
mv "${keyname}"* "${folder}/"
if [ $? -ne 0 ]; then
exit $?
fi

### Done
echo
echo "*** Key and certificate were created successfully and moved to '${folder}' folder"
echo "*** Use XMLSEC_TEST_UPDATE_XML_ON_FAILURE=yes make check-dsig to update the test files if needed."
echo


