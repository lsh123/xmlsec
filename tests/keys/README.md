# XMLSec Library: Unit test keys

## Passwords
The same password `secret123` should be used unless specified otherwise.

## Creating keys and certificates

### Create new CA
Change DAYS and CADAYS in the OpenSSL `CA.pl` script to 36500 (100 years)
Change default digest to sha256
Change key bits to 2048

```
export SSLEAY_CONFIG="-config ./openssl.cnf"
perl CA.pl -newca
cp ./demoCA/cacert.pem .
cp ./demoCA/private/cakey.pem .

openssl rsa -inform PEM -outform DER -traditional -in cakey.pem -out cakey.der
openssl x509 -outform DER -in cacert.pem -out cacert.der
```

#### Remember values and replace in all tests

```
./scripts/print-cert-info.sh cacert.pem

** Validity: ***
Not Before: Mar  8 22:04:47 2026 GMT
Not After : Feb 12 22:04:47 2126 GMT

** Subject Name: ***
C=US, ST=California, O=XML Security Library (http://www.aleksey.com/xmlsec), OU=Root CA, CN=Aleksey Sanin, emailAddress=xmlsec@aleksey.com

** Issuer Name: ***
C=US, ST=California, O=XML Security Library (http://www.aleksey.com/xmlsec), OU=Root CA, CN=Aleksey Sanin, emailAddress=xmlsec@aleksey.com

** Issuer Serial: ***
680572598617295163017172295025714171905498632014

** SKI: ***
M3la5AFDTmB5BK2SzKDDAMxuEEQ=

** Digest( SHA1 ): ***
Yh1v2nkn8ey/lOQvZTLXEVEhezE=

** Digest( SHA224 ): ***
ELQkaCnnn/MzVvpDCXZf/ztKwet06I5YMsN6IQ==

** Digest( SHA256 ): ***
YRUR3UCYtsvTFvFnU9UHFRrZo9imcTVPdMfw8BpVKQk=

** Digest( SHA384 ): ***
4CSWJrlWO+1aNTLWCYCgumbRFw/6WwvMD6744HGpQDLoFVnguYeZ2r8S1QBX/H4C

** Digest( SHA512 ): ***
yEAfGbAx03oA3KW+y4Bl0A9lGY8AiS4Gzd4CCDNUor+UtQltf05VeO1OfkOjmSZQ
5m59F7bTmgC9Yni/og1oRw==

** Digest( SHA3-224 ): ***
+QdSnTAFutODDQGShgwjQQj0I+KW8g+/zDn/qQ==

** Digest( SHA3-256 ): ***
TCOnoMHzeio9NnqeIPP83iooC59siXC2Nd8hmY0ngNw=

** Digest( SHA3-384 ): ***
LkyiHFleOwHlX7DpaskX2AR8UHS3dkE2sluXAAKyj4dVPUmeBfwDhh+1C4tm8K8p

** Digest( SHA3-512 ): ***
9PfhTtLpiw70lVWAJ+aA4hy7nNnc7pHhagbgFrO11bbM7kLP34ESIsgS6HJwKWc3
2l3Zb3bLPxMzm+w3p3NNkQ==

```

### Generate RSA key and a second level certificate
```
openssl genrsa -out ca2key.pem
openssl req -config ./openssl.cnf -new -key ca2key.pem -out ca2req.pem
openssl ca -config ./openssl.cnf -cert cacert.pem -keyfile cakey.pem \
        -out ca2cert.pem -infiles ca2req.pem
openssl verify -CAfile cacert.pem ca2cert.pem
rm ca2req.pem


openssl rsa -inform PEM -outform DER -traditional -in ca2key.pem -out ca2key.der
openssl x509 -outform DER -in ca2cert.pem -out ca2cert.der

```

#### Remember values and replace in all tests


```
./scripts/print-cert-info.sh ca2cert.pem

** Validity: ***
Not Before: Mar  8 22:07:42 2026 GMT
Not After : Feb 12 22:07:42 2126 GMT

** Subject Name: ***
C=US, ST=California, O=XML Security Library (http://www.aleksey.com/xmlsec), OU=Second level CA, CN=Aleksey Sanin, emailAddress=xmlsec@aleksey.com

** Issuer Name: ***
C=US, ST=California, O=XML Security Library (http://www.aleksey.com/xmlsec), OU=Root CA, CN=Aleksey Sanin, emailAddress=xmlsec@aleksey.com

** Issuer Serial: ***
680572598617295163017172295025714171905498632015

** SKI: ***
0X0XrEVCio75sBcl1TxymJ2IOiU=

** Digest( SHA1 ): ***
ITOr7qNHWZwjGjCxTeN4wj+c05w=

** Digest( SHA224 ): ***
Su1PcyQdCDXozZCb4tUNEKCT3Dg2W+Ek+b85HQ==

** Digest( SHA256 ): ***
f8KWWGMregazVv77Mw49A/Oicjd5+wKvabdY2YfCGJM=

** Digest( SHA384 ): ***
rH9qTN2cAcovTEY3r8hIwtMpl5O/TOCbsJhROqKi9rZWgkA6X8HQwS52n5yL71yb

** Digest( SHA512 ): ***
FNQ+V2gqs3/iDH0wVX4LgD9NrpUQhVZagsprDp42ZqmshnJjgRyPzOj++vqoghmv
FLVP3GJNhVZAQ8t38EBmmw==

** Digest( SHA3-224 ): ***
HRaSUzyBXNVKYtsiWFvv3ttDSO/NjxxtQlBRbg==

** Digest( SHA3-256 ): ***
axK8pS4lQMuLbMBgpH8kTsa9e4zJto+5NWFIGKXh8aQ=

** Digest( SHA3-384 ): ***
qTsu2gcI21QgdajWv3dG4a8XyMHLzyeM269/LsU8255TxdhFnmOf6Y9bOXirRXZT

** Digest( SHA3-512 ): ***
54UFyARlf0bv8UxzmkPi1plr5D499QwrBCR2/UUeALpDzycbBSgVF6dQBNjUU2WC
lvzO56h5b1ix79poJNuA3A==

```


### Generate and sign DSA keys with second level CA
```
mkdir dsa
./scripts/create-dsa-1024.sh
./scripts/create-dsa-2048.sh
./scripts/create-dsa-3072.sh
```

### Generate and sign RSA keys with second level CA

Note: CRL need to be regenerated a few days later. This is needed for a test where certificates
are already valid by time but CRL is not yet.

```
mkdir rsa
./scripts/create-rsa-2048.sh
./scripts/create-rsa-2048-crl.sh
./scripts/create-rsa-4096.sh
./scripts/create-rsa-expired.sh
```


#### Remember values and replace in all tests
```
./scripts/print-cert-info.sh rsa/rsa-4096-cert.pem

** Validity: ***
Not Before: Mar  8 22:14:27 2026 GMT
Not After : Feb 12 22:14:27 2126 GMT

** Subject Name: ***
C=US, ST=California, O=XML Security Library (http://www.aleksey.com/xmlsec), CN=Test Key rsa-4096

** Issuer Name: ***
C=US, ST=California, O=XML Security Library (http://www.aleksey.com/xmlsec), OU=Second level CA, CN=Aleksey Sanin, emailAddress=xmlsec@aleksey.com

** Issuer Serial: ***
680572598617295163017172295025714171905498632020

** SKI: ***
60zMLKCfzQ3qnXAzABzRNpdgQ8Q=

** Digest( SHA1 ): ***
EpvJf6ehbVr0WoYoT1XKQcc4cjY=

** Digest( SHA224 ): ***
PytiHkMJ7MTFN5hxIbADUE+nRFRwGOtyWXGEQQ==

** Digest( SHA256 ): ***
fZd23DD+/7HSo72ZyFMENaMmbxjDF2SfThmux0P6qTY=

** Digest( SHA384 ): ***
7sW11odRYIK2BK9UAs+iyfy/+JQhxNAhr3SzLSdNUxXxM8CzIwAAsxNAAL62uu+P

** Digest( SHA512 ): ***
KRwh8Pv3wdTVlPlwwfc1wEygbxzxCtffw/A0zv7ChDV2Wgm3hSrvCAQXE0+5grrE
yTlxGTAsUCDBkpj+2LWRyw==

** Digest( SHA3-224 ): ***
/fhhzcIh8RAg+OY+Nsj4i7YB0Q6mrK6Hh8uHxQ==

** Digest( SHA3-256 ): ***
YR+o/+utXWp+dE+PMD175PFDp2SGIKPb+pCTlCbsads=

** Digest( SHA3-384 ): ***
CjKuz7An+LLYBlw4H352BkMvXi27+c64HdrHKCVN2bF9R7kex/ubildZGtCQpbjO

** Digest( SHA3-512 ): ***
AO4amGZNPllXK6SQLgWD+9FI1BG+hU3+tMzcuhwv3gYQW7VC2AdYb8oVC2jzHAr/
Y35Ao0pe1DXmo6/+wGWDfA==


```


* Creating NSS DB
DO NOT SPECIFY PASSWORD FOR NSS DB (private keys pkcs12 password is 'secret123')

```
rm -rf nssdb
mkdir nssdb
pk12util -d nssdb -i rsa/rsa-4096-key.p12
chmod a-w nssdb/*
```


### Generate EC keys with second level CA
```
mkdir ec
./scripts/create-ec-prime256v1.sh
./scripts/create-ec-prime256v1-second.sh
./scripts/create-ec-prime384v1.sh
./scripts/create-ec-prime384v1-second.sh
./scripts/create-ec-prime521v1.sh
./scripts/create-ec-prime521v1-second.sh
```

### Generate and sign DHX keys with second level CA
```
mkdir dhx
./scripts/create-dhx-rfc5114-3-first.sh
./scripts/create-dhx-rfc5114-3-second.sh
```

### Generate ML-DSA keys with second level CA

```
mkdir ml-dsa
./scripts/create-ml-dsa-44.sh
./scripts/create-ml-dsa-65.sh
./scripts/create-ml-dsa-87.sh
```

### Generate SLH-DSA keys with second level CA

```
mkdir slh-dsa
./scripts/create-slh-dsa-sha2-128f.sh
./scripts/create-slh-dsa-sha2-128s.sh
./scripts/create-slh-dsa-sha2-192f.sh
./scripts/create-slh-dsa-sha2-192s.sh
./scripts/create-slh-dsa-sha2-256f.sh
./scripts/create-slh-dsa-sha2-256s.sh
```


### Generate EdDSA keys with second level CA

```
mkdir eddsa
./scripts/create-eddsa-ed25519.sh
./scripts/create-eddsa-ed448.sh
```

### Generate XDH keys
```
mkdir xdh

./scripts/create-xdh-x25519-first.sh
./scripts/create-xdh-x25519-second.sh

./scripts/create-xdh-x448-first.sh
./scripts/create-xdh-x448-second.sh
```

### Generate two certs and keys with the same certificate
```
openssl req -x509 -newkey rsa:2048 -keyout same-subj-key1.pem -out same-subj-cert1.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
openssl req -x509 -newkey rsa:2048 -keyout same-subj-key2.pem -out same-subj-cert2.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"

openssl x509 -in same-subj-cert1.pem -out same-subj-cert1.der --outform DER
openssl x509 -in same-subj-cert2.pem -out same-subj-cert2.der --outform DER

openssl rsa -in same-subj-key1.pem -out same-subj-key1.der --outform DER
openssl rsa -in same-subj-key2.pem -out same-subj-key2.der --outform DER
```


### Generate and sign GOST2001 and GOST2012 keys with second level CA
To enable GOST support, modify openssl.conf file:
- uncomment the `# gost = gost_section` line'
- specify correct path to `gost.so` in the `dynamic_path` variable in the `gost_section` section

```
export OPENSSL_TOP_DIR=<path to openssl>
export PATH=$OPENSSL_TOP_DIR/bin:$PATH
export LD_LIBRARY_PATH=$OPENSSL_TOP_DIR/lib64:$OPENSSL_TOP_DIR/lib:$LD_LIBRARY_PATH
OPENSSL_CONF=./openssl.cnf openssl version -e
OPENSSL_CONF=./openssl.cnf openssl engine

OPENSSL_CONF=./openssl.cnf ./scripts/create-gost-2001.sh
OPENSSL_CONF=./openssl.cnf ./scripts/create-gost-2012-256.sh
OPENSSL_CONF=./openssl.cnf ./scripts/create-gost-2012-512.sh
```
