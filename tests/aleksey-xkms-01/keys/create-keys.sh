#!/bin/sh
#
# This script along with "openssl.cnf" file from this folder creates 
# a chain of three certificates containing RSA 1024 keys:
#	cert1 (key1) - root CA certificate (self signed).
#	cert2 (key2) - second level CA certificate (signed with key1/cert1)
#	cert3 (key3) - signature/encryption certificate (signed with key2/cert2)
# All the private keys are encrypted with password "secret". 
#
export CA_TOP=./demoCA
export CA_PWD=secret

echo "Remove old file"
rm -rf "$CA_TOP" *.pem *.der *.p12 *.req

echo "Create CA folders structure"
mkdir "$CA_TOP"
mkdir "${CA_TOP}/certs"
mkdir "${CA_TOP}/crl"
mkdir "${CA_TOP}/newcerts"
mkdir "${CA_TOP}/private"
echo "01" > "$CA_TOP/serial"
touch "$CA_TOP/index.txt"

echo "Create root key and certificate"
export CERT_NAME="aleksey-xkms-01 root certificate"
openssl req -config ./openssl.cnf -new -x509 -keyout key1.pem -out cert1.pem -batch

echo "Generate RSA key and second level certificate"
export CERT_NAME="aleksey-xkms-01 second level certificate"
openssl genrsa -out key2.pem
openssl req -config ./openssl.cnf -batch -new -key key2.pem -out req2.pem
openssl ca  -config ./openssl.cnf -passin pass:$CA_PWD -batch -extensions v3_ca -cert cert1.pem -keyfile key1.pem -out cert2.pem -infiles req2.pem 
	
echo "Generate another RSA key and third level certificate"
export CERT_NAME="aleksey-xkms-01 signature and encryption certificate"
openssl genrsa -out key3.pem
openssl req -config ./openssl.cnf -batch -new -key key3.pem -out req3.pem
openssl ca  -config ./openssl.cnf -passin pass:$CA_PWD -batch -cert cert2.pem -keyfile key2.pem -out cert3.pem -infiles req3.pem

echo "Convert all private keys to der, pkcs8/der and pkcs12 format"
openssl rsa -passin pass:$CA_PWD -passout pass:$CA_PWD -inform PEM -outform DER -in key1.pem -out key1.der
openssl rsa -passin pass:$CA_PWD -passout pass:$CA_PWD -inform PEM -outform DER -in key2.pem -out key2.der
openssl rsa -passin pass:$CA_PWD -passout pass:$CA_PWD -inform PEM -outform DER -in key3.pem -out key3.der

openssl pkcs8 -passin pass:$CA_PWD -passout pass:$CA_PWD -in key1.pem -inform pem -out key1-pk8.der -outform der -topk8
openssl pkcs8 -passin pass:$CA_PWD -passout pass:$CA_PWD -in key2.pem -inform pem -out key2-pk8.der -outform der -topk8
openssl pkcs8 -passin pass:$CA_PWD -passout pass:$CA_PWD -in key3.pem -inform pem -out key3-pk8.der -outform der -topk8
	    
openssl pkcs12 -passin pass:$CA_PWD -passout pass:$CA_PWD -export -in cert1.pem -inkey key1.pem -name key1 -out key1.p12
openssl pkcs12 -passin pass:$CA_PWD -passout pass:$CA_PWD -export -in cert2.pem -inkey key2.pem -name key2 -out key2.p12
openssl pkcs12 -passin pass:$CA_PWD -passout pass:$CA_PWD -export -in cert3.pem -inkey key3.pem -name key3 -out key3.p12
	
echo "Convert all certificates to der format"
openssl x509 -outform DER -in cert1.pem -out cert1.der 
openssl x509 -outform DER -in cert2.pem -out cert2.der 
openssl x509 -outform DER -in cert3.pem -out cert3.der 

echo "View certificates"
openssl x509 -noout -text -in cert1.pem
openssl x509 -noout -text -in cert2.pem
openssl x509 -noout -text -in cert3.pem

echo "Test certificates"
openssl verify -CAfile cert1.pem cert2.pem
openssl verify -CAfile cert1.pem -untrusted cert2.pem cert3.pem
    

echo "Cleanup"
rm -rf "$CA_TOP" *.req
	
	
	