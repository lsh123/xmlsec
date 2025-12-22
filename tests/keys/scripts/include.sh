#!/bin/sh
#
# Include this file into key creation script to setup common variables and get common functions
#
openssl_conf="./openssl.cnf"
ca_file="./cacert.pem"
second_level_ca_key_file="./ca2key.pem"
second_level_ca_file="./ca2cert.pem"
password="secret123"

if [ ! -f "${openssl_conf}" ] ; then
    echo "Error: openssl config file '${openssl_conf}' not found!"
    echo "Please run this script from the tests/keys/ folder."
    exit 1
fi

create_private_key()
{
    local keyname="$1"
    local algorithm="$2"
    local genpkey_options="$3"

    ### Create private key
    echo
    echo "*** Generating ${algorithm} key ${keyname}...."
    echo
    openssl genpkey -genparam  -algorithm "${algorithm}" ${genpkey_options} -out "${keyname}-param.pem"
    openssl genpkey -paramfile "${keyname}-param.pem" -out "${keyname}-key.pem"
    rm "${keyname}-param.pem"

    echo "*** Private key '${keyname}-key.pem' was created successfully"
}

create_public_key_from_private_key()
{
    local keyname="$1"

    ### Create public key
    openssl pkey -in "${keyname}-key.pem" -pubout -out "${keyname}-pubkey.pem"

    echo "*** Public key '${keyname}-pubkey.pem' was created successfully"
}

create_der_keys_from_private_and_public_key()
{
    local keyname="$1"

    ### Create DER files
    echo
    echo "*** Creating DER files.."
    echo
    openssl pkey -in "${keyname}-key.pem" -outform DER -out "${keyname}-key.der"
    openssl pkey -in "${keyname}-key.pem" -pubout -outform DER -out "${keyname}-pubkey.der"

    echo "*** DER files '${keyname}-key.der' and '${keyname}-pubkey.der' were created successfully"
}

create_pkcs8_keys_from_private_key()
{
    local keyname="$1"

    ### Create PKCS8 files
    echo
    echo "*** Creating PKCS8 files..."
    echo
    openssl pkcs8 -in "${keyname}-key.pem" -inform pem -out "${keyname}-key.p8-pem" -outform pem -topk8 -passout pass:"${password}"
    openssl pkcs8 -in "${keyname}-key.pem" -inform pem -out "${keyname}-key.p8-der" -outform der -topk8 -passout pass:"${password}"

    echo "*** PKCS8 files '${keyname}-key.p8-pem' and '${keyname}-key.p8-der' were created successfully"
}

create_certificate_from_private_key() {
    local keyname="$1"
    local gencert_options="$2"
    local subject="/CN=Test Key ${keyname}/O=XML Security Library \(http:\/\/www.aleksey.com\/xmlsec\)/ST=California/C=US"

    # allow overwrites
    local config_option=""
    if [ -n "$OPENSSL_CONF" ]; then
        echo "*** Using OPENSSL_CONF from environment: ${OPENSSL_CONF} ***"
    else
        config_option="-config ${openssl_conf}"
    fi

    ### Create certificate signed by second level CA
    echo
    echo "*** Signing using second level CA...."
    echo
    openssl req ${config_option} -new -key "${keyname}-key.pem" ${gencert_options} -subj "${subject}" -out "${keyname}-req.pem"
    yes | openssl ca ${config_option} ${gencert_options} -cert "${second_level_ca_file}" -keyfile "${second_level_ca_key_file}" -notext -out "${keyname}-cert.pem" -infiles "${keyname}-req.pem"
    openssl verify -CAfile "${ca_file}" -untrusted "${second_level_ca_file}" "${keyname}-cert.pem"
    rm "${keyname}-req.pem"

    openssl x509 -in "${keyname}-cert.pem" -inform PEM -out "${keyname}-cert.der" -outform DER
    cp "${keyname}-cert.der" "${keyname}-pubkey.crt"

    echo "*** Certificate files '${keyname}-cert.pem' and '${keyname}-cert.der' were created successfully"
}

create_pkcs12_from_private_key_and_cert() {
    local keyname="$1"
    local pkcs12_name="TestKeyName-${keyname}"
    local ms_csp="Microsoft Enhanced Cryptographic Provider v1.0"

    ### Create PKCS12 file
    echo
    echo "*** Creating PKCS12 files..."
    echo
    cat "${keyname}-key.pem" "${keyname}-cert.pem" "${second_level_ca_file}" "${ca_file}" > "all-${keyname}.pem"
    openssl pkcs12 -export -in "all-${keyname}.pem" -name "${pkcs12_name}" -out "${keyname}-key.p12" -passout pass:"${password}"

    ### Add Crypto Service Provider (CSP) for Windows
    # On Windows, one needs to specify Crypto Service Provider (CSP) in the pkcs12 file
    # to ensure it is loaded correctly to be used with SHA2 algorithms. Worse, the CSP is
    # different for XP and older versions.
    openssl pkcs12 -export -in "all-${keyname}.pem" -name "${pkcs12_name}" -out "${keyname}-key-win.p12" -CSP "${ms_csp}" -passout pass:"${password}"

    ### cleanup
    rm "all-${keyname}.pem"

    ### done
    echo "*** PKCS12 file '${keyname}-key.p12' with key name '${pkcs12_name}' was created successfully"
}

create_all_key_files_from_private_key()
{
    local keyname="$1"

    create_public_key_from_private_key "${keyname}"
    create_der_keys_from_private_and_public_key "${keyname}"
    create_pkcs8_keys_from_private_key "${keyname}"
}

#
# High level key creation function
#
create_key() {
    local keyname="$1"
    local algorithm="$2"
    local genpkey_options="$3"

    ### Create private key
    create_private_key "${keyname}" "${algorithm}" "${genpkey_options}"

    ### Create all key files from private key
    create_all_key_files_from_private_key "${keyname}"

    ### Done
    echo
    echo "*** Key was created successfully: Use XMLSEC_TEST_UPDATE_XML_ON_FAILURE=yes make check-dsig to update the test files if needed."
    echo
}

create_key_with_second_level_ca() {
    local keyname="$1"
    local algorithm="$2"
    local genpkey_options="$3"
    local gencert_options="$4"

    ### Create private key
    create_private_key "${keyname}" "${algorithm}" "${genpkey_options}"

    ### Create all key files from private key
    create_all_key_files_from_private_key "${keyname}"

    ### Create certificate signed by second level CA
    create_certificate_from_private_key "${keyname}" "${gencert_options}"

    ### Create PKCS12 file
    create_pkcs12_from_private_key_and_cert "${keyname}"

    ### Done
    echo
    echo "*** Key and certificate were created successfully: Use XMLSEC_TEST_UPDATE_XML_ON_FAILURE=yes make check-dsig to update the test files if needed."
    echo
}

