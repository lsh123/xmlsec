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

create_key_with_second_level_ca() {
    local keyname="$1"
    local algorithm="$2"
    local genpkey_options="$3"
    local subject="/C=US/ST=California/O=XML Security Library \(http:\/\/www.aleksey.com\/xmlsec\)/CN=Test Key ${keyname}"
    local pkcs12_name="TestKeyName-${keyname}"


    ###
    echo
    echo "*** Generating ${algorithm} key with key name ${pkcs12_name} using second level CA...."
    echo
    openssl genpkey -algorithm "${algorithm}" ${genpkey_options} -out "${keyname}-key.pem"
    openssl pkey -in "${keyname}-key.pem" -pubout -out "${keyname}-pubkey.pem"

    openssl req -config "${openssl_conf}" -new -key "${keyname}-key.pem" -subj "${subject}" -out "${keyname}-req.pem"
    yes | openssl ca -config "${openssl_conf}" -cert "${second_level_ca_file}" -keyfile "${second_level_ca_key_file}" -out "${keyname}-cert.pem" -infiles "${keyname}-req.pem"
    openssl verify -CAfile "${ca_file}" -untrusted "${second_level_ca_file}" "${keyname}-cert.pem"
    rm "${keyname}-req.pem"

    openssl x509 -in "${keyname}-cert.pem" -inform PEM -out "${keyname}-cert.der" -outform DER
    cp "${keyname}-cert.der" "${keyname}-pubkey.crt"

    ###
    echo
    echo "*** Creating DER files.."
    echo
    openssl pkey -in "${keyname}-key.pem" -outform DER -out "${keyname}-key.der"
    openssl pkey -in "${keyname}-key.pem" -pubout -outform DER -out "${keyname}-pubkey.der"

    ###
    echo
    echo "*** Creating PKCS8 files..."
    echo
    openssl pkcs8 -in "${keyname}-key.der" -inform der -out "${keyname}-key.p8-pem" -outform pem -topk8 -passout pass:"${password}"
    openssl pkcs8 -in "${keyname}-key.der" -inform der -out "${keyname}-key.p8-der" -outform der -topk8 -passout pass:"${password}"

    ###
    echo
    echo "*** Creating PKCS12 file..."
    echo
    cat "${keyname}-key.pem" "${keyname}-cert.pem" "${second_level_ca_file}" "${ca_file}" > "all-${keyname}.pem"
    openssl pkcs12 -export -in "all-${keyname}.pem" -name "${pkcs12_name}" -out "${keyname}-key.p12" -passout pass:"${password}"
    rm "all-${keyname}.pem"

    ###
    echo
    echo "*** Key created successfully: key name: ${pkcs12_name}; files: ${keyname}*"
    echo "Use XMLSEC_TEST_UPDATE_XML_ON_FAILURE=yes make check-dsig to update the test files if needed."
    echo
}

