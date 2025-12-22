# XMLSec Library: Unit test keys

## Passwords
The same password `secret123` should be used unless specified otherwise.

## Creating keys and certificates

### Create new CA
Change DAYS and CADAYS in the OpenSSL `CA.pl` script to 36500 (100 years)

```
export SSLEAY_CONFIG="-config ./openssl.cnf"
CA.pl -newca
cp ./demoCA/cacert.pem .
cp ./demoCA/private/cakey.pem .
openssl x509 -text -in cacert.pem


openssl rsa -inform PEM -outform DER -traditional -in cakey.pem -out cakey.der
openssl x509 -outform DER -in cacert.pem -out cacert.der

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


### Generate and sign DSA keys with second level CA
```
./scripts/create-dsa-1024.sh
./scripts/create-dsa-2048.sh
./scripts/create-dsa-3072.sh
```

### Generate and sign RSA keys with second level CA

```
./scripts/create-rsa-2048.sh
./scripts/create-rsa-4096.sh
./scripts/create-rsa-expired.sh
```

* Creating NSS DB
DO NOT SPECIFY PASSWORD FOR NSS DB (private keys pkcs12 password is 'secret123')

```
rm -rf nssdb
mkdir nssdb
pk12util -d nssdb -i rsa-4096-key.p12
chmod a-w nssdb/*
```


### Generate EC keys with second level CA
```
./scripts/create-ec-prime256v1.sh
./scripts/create-ec-prime256v1-second.sh
./scripts/create-ec-prime384v1.sh
./scripts/create-ec-prime521v1.sh
```

### Generate and sign DHX keys with second level CA
```
./scripts/create-dhx-rfc5114-3-first.sh
./scripts/create-dhx-rfc5114-3-second.sh
```

### Generate ML-DSA keys with second level CA

```
./scripts/create-ml-dsa-44.sh
./scripts/create-ml-dsa-86.sh
./scripts/create-ml-dsa-87.sh
```

### Generate SLH-DSA keys with second level CA

```
./scripts/create-slh-dsa-sha2-128f.sh
./scripts/create-slh-dsa-sha2-128s.sh
./scripts/create-slh-dsa-sha2-192f.sh
./scripts/create-slh-dsa-sha2-192s.sh
./scripts/create-slh-dsa-sha2-256f.sh
./scripts/create-slh-dsa-sha2-256s.sh
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

```



GOST2012 512 bits:
```
openssl req -config ./openssl.cnf -newkey gost2012_512 -pkeyopt paramset:A -nodes -keyout gost2012_512key.pem -out gost2012_512req.pem
openssl ca -config ./openssl.cnf -cert ca2cert.pem -keyfile ca2key.pem -out gost2012_512cert.pem -infiles gost2012_512req.pem
OPENSSL_CONF=./openssl.cnf openssl verify -CAfile cacert.pem -untrusted ca2cert.pem gost2012_512cert.pem
rm gost2012_512req.pem

openssl x509 -outform DER -in gost2012_512cert.pem -out gost2012_512cert.der

OPENSSL_CONF=./openssl.cnf openssl pkcs8 -in gost2012_512key.pem -inform pem -out gost2012_512key.p8-pem -outform pem -topk8

cat gost2012_512key.pem gost2012_512cert.pem ca2cert.pem cacert.pem > all-gost2012_512.pem
OPENSSL_CONF=./openssl.cnf openssl pkcs12 -export -in all-gost2012_512.pem -name TestGost2012_512Key -out gost2012_512key.p12
rm all-gost2012_512.pem

```
