# XMLSec Library: Unit test keys

## Passwords
The same password `secret` should be used unless specified otherwise.

## Creating keys and certificates

### Create new CA
Change DAYS and CADAYS in the OpenSSL `CA.pl` script to 36500 (100 years)

```
export SSLEAY_CONFIG="-config ./openssl.cnf"
CA.pl -newca
cp ./demoCA/cacert.pem .
cp ./demoCA/private/cakey.pem .
openssl x509 -text -in cacert.pem
```

### Generate RSA key and a second level certificate
```
openssl genrsa -out ca2key.pem
openssl req -config ./openssl.cnf -new -key ca2key.pem -out ca2req.pem
openssl ca -config ./openssl.cnf -cert cacert.pem -keyfile cakey.pem \
        -out ca2cert.pem -infiles ca2req.pem
openssl verify -CAfile cacert.pem ca2cert.pem
rm ca2req.pem
```

### Generate and sign DSA keys with second level CA (IMPORTANT: use OpenSSL 1.x for generating DSA keys!!!)


DSA 1024 bits (OU = Test Third Level DSA Certificate) :
```
openssl dsaparam -out dsakey.pem -genkey 1024
openssl req -config ./openssl.cnf -new -key dsakey.pem -out dsareq.pem
openssl ca -config ./openssl.cnf -cert ca2cert.pem -keyfile ca2key.pem -out dsacert.pem -infiles dsareq.pem
openssl verify -CAfile cacert.pem -untrusted ca2cert.pem dsacert.pem
rm dsareq.pem

openssl pkey -inform DER -in dsakey.der --outform DER --pubout --out dsapubkey.der
openssl pkey -inform DER -in dsakey.der --outform PEM --pubout --out dsapubkey.pem
```

DSA 2048 bits:
```
openssl dsaparam -out dsa2048key.pem -genkey 2048
openssl req -config ./openssl.cnf -new -key dsa2048key.pem -out dsa2048req.pem
openssl ca -config ./openssl.cnf -cert ca2cert.pem -keyfile ca2key.pem \
        -out dsa2048cert.pem -infiles dsa2048req.pem
openssl verify -CAfile cacert.pem -untrusted ca2cert.pem dsa2048cert.pem
rm dsa2048req.pem
```

DSA 3072 bits:
```
openssl dsaparam -out dsa3072key.pem -genkey 3072
openssl req -config ./openssl.cnf -new -key dsa3072key.pem -out dsa3072req.pem
openssl ca -config ./openssl.cnf -cert ca2cert.pem -keyfile ca2key.pem \
        -out dsa3072cert.pem -infiles dsa3072req.pem
openssl verify -CAfile cacert.pem -untrusted ca2cert.pem dsa3072cert.pem
rm dsa3072req.pem
```

### Generate and sign RSA keys with second level CA
RSA 2048 bits (OU="Test Third Level RSA Certificate"):
```
openssl genrsa -out rsakey.pem 2048
openssl req -config ./openssl.cnf -new -key rsakey.pem -out rsareq.pem
openssl ca -config ./openssl.cnf -cert ca2cert.pem -keyfile ca2key.pem \
        -out rsacert.pem -infiles rsareq.pem
openssl verify -CAfile cacert.pem -untrusted ca2cert.pem rsacert.pem
rm rsareq.pem
```

Revoke rsacert and generate CRL
```
openssl ca -config ./openssl.cnf -cert ca2cert.pem -keyfile ca2key.pem -revoke rsacert.pem
openssl ca -config ./openssl.cnf -cert ca2cert.pem -keyfile ca2key.pem -gencrl -out rsacert-revoked-crl.pem
openssl crl -in rsacert-revoked-crl.pem -inform PEM -outform DER -out rsacert-revoked-crl.der
```


RSA 4096 bits:
```
openssl genrsa -out largersakey.pem 4096
openssl req -config ./openssl.cnf -new -key largersakey.pem -out largersareq.pem
openssl ca -config ./openssl.cnf -cert ca2cert.pem -keyfile ca2key.pem \
        -out largersacert.pem -infiles largersareq.pem
openssl verify -CAfile cacert.pem -untrusted ca2cert.pem largersacert.pem
rm largersareq.pem

openssl pkey -inform DER -in largersakey.der --outform DER --pubout --out largersapubkey.der
openssl pkey -inform DER -in largersakey.der --outform PEM --pubout --out largersapubkey.pem
```


### Generate and sign short-live RSA cert for "expired cert" test (OU = "Test Expired RSA Certificate")
```
openssl genrsa -out expiredkey.pem 2048
openssl req -config ./openssl.cnf -new -days 1 -key expiredkey.pem -out expiredreq.pem
openssl ca -config ./openssl.cnf -days 1 -cert ca2cert.pem -keyfile ca2key.pem -out expiredcert.pem -infiles expiredreq.pem
openssl verify -CAfile cacert.pem -untrusted ca2cert.pem expiredcert.pem
rm expiredreq.pem
```

### Generate ECDSA prime256v1 key with second level CA
```
openssl ecparam -list_curves
openssl ecparam -name prime256v1 -genkey -noout -out ec-prime256v1-key.pem
    Here use 'EC prime256v1 Key' for OU:
openssl req -config ./openssl.cnf -new -key ec-prime256v1-key.pem -out ec-prime256v1-req.pem
openssl ca -config ./openssl.cnf -cert ca2cert.pem -keyfile ca2key.pem -out ec-prime256v1-cert.pem -infiles ec-prime256v1-req.pem
openssl verify -CAfile cacert.pem -untrusted ca2cert.pem ec-prime256v1-cert.pem
rm ec-prime256v1-req.pem

openssl x509 -in ec-prime256v1-cert.pem -inform PEM -out ec-prime256v1-cert.der -outform DER
cp ec-prime256v1-cert.der ec-prime256v1-key.crt

openssl pkey -inform PEM -in ec-prime256v1-key.pem --outform DER --out  ec-prime256v1-key.der
openssl pkey -inform PEM -in ec-prime256v1-key.pem --outform DER --pubout --out  ec-prime256v1-pubkey.der
openssl pkey -inform PEM -in ec-prime256v1-key.pem --outform PEM --pubout --out  ec-prime256v1-pubkey.pem
```

### Generate a second ECDSA prime256v1 key with second level CA
```
openssl ecparam -list_curves
openssl ecparam -name prime256v1 -genkey -noout -out ec-prime256v1-second-key.pem
    Here use 'EC prime256v1 Second Key' for OU:
openssl req -config ./openssl.cnf -new -key ec-prime256v1-second-key.pem -out ec-prime256v1-second-req.pem
openssl ca -config ./openssl.cnf -cert ca2cert.pem -keyfile ca2key.pem -out ec-prime256v1-second-cert.pem -infiles ec-prime256v1-second-req.pem
openssl verify -CAfile cacert.pem -untrusted ca2cert.pem ec-prime256v1-second-cert.pem
rm ec-prime256v1-second-req.pem

openssl x509 -in ec-prime256v1-second-cert.pem -inform PEM -out ec-prime256v1-second-cert.der -outform DER
cp ec-prime256v1-second-cert.der ec-prime256v1-second-key.crt

openssl pkey -inform PEM -in ec-prime256v1-second-key.pem --outform DER --out  ec-prime256v1-second-key.der
openssl pkey -inform PEM -in ec-prime256v1-second-key.pem --outform DER --pubout --out  ec-prime256v1-second-pubkey.der
openssl pkey -inform PEM -in ec-prime256v1-second-key.pem --outform PEM --pubout --out  ec-prime256v1-second-pubkey.pem
```


### Generate ECDSA secp256r1 key with second level CA
```
openssl ecparam -list_curves
openssl ecparam -name secp256r1 -genkey -noout -out ecdsa-secp256r1-key.pem
    Here use 'ECDSA secp256r1 Key' for Common Name:
openssl req -config ./openssl.cnf -new -key ecdsa-secp256r1-key.pem -out ecdsa-secp256r1-req.pem
openssl ca -config ./openssl.cnf -cert ca2cert.pem -keyfile ca2key.pem \
        -out ecdsa-secp256r1-cert.pem -infiles ecdsa-secp256r1-req.pem
openssl verify -CAfile cacert.pem -untrusted ca2cert.pem ecdsa-secp256r1-cert.pem
rm ecdsa-secp256r1-req.pem

openssl pkey -inform DER -in ecdsa-secp256r1-key.der --outform DER --pubout --out  ecdsa-secp256r1-pubkey.der
openssl pkey -inform DER -in ecdsa-secp256r1-key.der --outform PEM --pubout --out  ecdsa-secp256r1-pubkey.pem
```

### Generate second ECDSA secp256r1 key with second level CA
```
openssl ecparam -list_curves
openssl ecparam -name secp256r1 -genkey -noout -out ecdsa-secp256r1-second-key.pem
    Here use 'ECDSA secp256r1 Second Key' for OU:
openssl req -config ./openssl.cnf -new -key ecdsa-secp256r1-second-key.pem -out ecdsa-secp256r1-second-req.pem
openssl ca -config ./openssl.cnf -cert ca2cert.pem -keyfile ca2key.pem -out ecdsa-secp256r1-second-cert.pem -infiles ecdsa-secp256r1-second-req.pem
openssl verify -CAfile cacert.pem -untrusted ca2cert.pem ecdsa-secp256r1-second-cert.pem
rm ecdsa-secp256r1-second-req.pem

openssl x509 -in ecdsa-secp256r1-second-cert.pem -inform PEM -out ecdsa-secp256r1-second-cert.der -outform DER
cp ecdsa-secp256r1-second-cert.der ecdsa-secp256r1-second-key.crt

openssl pkey -inform PEM -in ecdsa-secp256r1-second-key.pem --outform DER --out  ecdsa-secp256r1-second-key.der
openssl pkey -inform PEM -in ecdsa-secp256r1-second-key.pem --outform DER --pubout --out  ecdsa-secp256r1-second-pubkey.der
openssl pkey -inform PEM -in ecdsa-secp256r1-second-key.pem --outform PEM --pubout --out  ecdsa-secp256r1-second-pubkey.pem
```

### Generate ECDSA 384 key with second level CA
```
openssl ecparam -list_curves
openssl ecparam -name secp384r1 -genkey -noout -out ecdsa-secp384r1-key.pem
    Here use 'ECDSA secp384r1 Key' for Common Name:
openssl req -config ./openssl.cnf -new -key ecdsa-secp384r1-key.pem -out ecdsa-secp384r1-req.pem
openssl ca -config ./openssl.cnf -cert ca2cert.pem -keyfile ca2key.pem \
        -out ecdsa-secp384r1-cert.pem -infiles ecdsa-secp384r1-req.pem
 openssl verify -CAfile cacert.pem -untrusted ca2cert.pem ecdsa-secp384r1-cert.pem
 rm ecdsa-secp384r1-req.pem
```

### Generate ECDSA 512 key with second level CA
```
openssl ecparam -list_curves
openssl ecparam -name secp521r1 -genkey -noout -out ecdsa-secp521r1-key.pem
    Here use 'ECDSA secp521r1 Key' for Common Name:
openssl req -config ./openssl.cnf -new -key ecdsa-secp521r1-key.pem -out ecdsa-secp521r1-req.pem
openssl ca -config ./openssl.cnf -cert ca2cert.pem -keyfile ca2key.pem \
        -out ecdsa-secp521r1-cert.pem -infiles ecdsa-secp521r1-req.pem
 openssl verify -CAfile cacert.pem -untrusted ca2cert.pem ecdsa-secp521r1-cert.pem
 rm ecdsa-secp521r1-req.pem
```

### Generate and sign DHX keys with second level CA
```
openssl genpkey -algorithm DHX -genparam -pkeyopt dh_paramgen_prime_len:1024 -pkeyopt dh_paramgen_type:1 -pkeyopt dh_rfc5114:1 -out dh1024-params.pem
openssl genpkey -paramfile dh1024-params.pem -out dh1024-first-key.pem
openssl genpkey -paramfile dh1024-params.pem -out dh1024-second-key.pem
rm dh1024-params.pem

openssl pkey -inform PEM -in dh1024-first-key.pem --outform DER --out dh1024-first-key.der
openssl pkey -inform PEM -in dh1024-first-key.pem --outform DER --pubout --out dh1024-first-pubkey.der
openssl pkey -inform PEM -in dh1024-first-key.pem --outform PEM --pubout --out dh1024-first-pubkey.pem

openssl pkey -inform PEM -in dh1024-second-key.pem --outform DER --out dh1024-second-key.der
openssl pkey -inform PEM -in dh1024-second-key.pem --outform DER --pubout --out dh1024-second-pubkey.der
openssl pkey -inform PEM -in dh1024-second-key.pem --outform PEM --pubout --out dh1024-second-pubkey.pem
```


DH 1024 bits (OU = First DHX-1024 Certificate)
X509 req failed with error "operation not supported for this keytype":
```
openssl req -config ./openssl.cnf -new -key dh1024-first-key.pem -out dh1024-first-req.pem
openssl ca -config ./openssl.cnf -cert ca2cert.pem -keyfile ca2key.pem -out dh1024-first-pubkey.crt -infiles dh1024-first-req.pem
openssl verify -CAfile cacert.pem -untrusted ca2cert.pem dh1024-first-pubkey.crt
rm dh1024-first-req.pem
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

GOST2001:
```
openssl req -config ./openssl.cnf -newkey gost2001 -pkeyopt paramset:A -nodes -keyout gost2001key.pem -out gost2001req.pem
openssl ca -config ./openssl.cnf -cert ca2cert.pem -keyfile ca2key.pem -out gost2001cert.pem -infiles gost2001req.pem
OPENSSL_CONF=./openssl.cnf openssl verify -CAfile cacert.pem -untrusted ca2cert.pem gost2001cert.pem
rm gost2001req.pem
```

GOST2012 256 bits:
```
openssl req -config ./openssl.cnf -newkey gost2012_256 -pkeyopt paramset:A -nodes -keyout gost2012_256key.pem -out gost2012_256req.pem
openssl ca -config ./openssl.cnf -cert ca2cert.pem -keyfile ca2key.pem -out gost2012_256cert.pem -infiles gost2012_256req.pem
OPENSSL_CONF=./openssl.cnf openssl verify -CAfile cacert.pem -untrusted ca2cert.pem gost2012_256cert.pem
rm gost2012_256req.pem
```

GOST2012 512 bits:
```
openssl req -config ./openssl.cnf -newkey gost2012_512 -pkeyopt paramset:A -nodes -keyout gost2012_512key.pem -out gost2012_512req.pem
openssl ca -config ./openssl.cnf -cert ca2cert.pem -keyfile ca2key.pem -out gost2012_512cert.pem -infiles gost2012_512req.pem
OPENSSL_CONF=./openssl.cnf openssl verify -CAfile cacert.pem -untrusted ca2cert.pem gost2012_512cert.pem
rm gost2012_512req.pem
```

## Converting key and certs between PEM and DER formats

### Convert PEM private key file to DER file

Some libraries (e.g GCrypt) don't like the newer versions of DER formats. So we use
old (traditional, ASN1, etc) formats instead

RSA keys:
```
openssl rsa -inform PEM -outform DER -traditional -in rsakey.pem -out rsakey.der
openssl rsa -inform PEM -outform DER -traditional -in largersakey.pem -out largersakey.der
openssl rsa -inform PEM -outform DER -traditional -pubin -RSAPublicKey_out -in largersapubkey.pem -out largersapubkey-gcrypt.der
openssl rsa -inform PEM -outform DER -traditional -in expiredkey.pem -out expiredkey.der
openssl rsa -inform PEM -outform DER -traditional -in ca2key.pem -out ca2key.der
```

DSA keys:
```
openssl dsa -inform PEM -outform DER -in dsakey.pem -out dsakey.der
openssl dsa --inform PEM -in dsapubkey.pem -pubin -outform D -out dsapubkey.der
openssl dsa -inform PEM -outform DER -in dsa2048key.pem -out dsa2048key.der
openssl dsa -inform PEM -outform DER -in dsa3072key.pem -out dsa3072key.der
```

EC keys:
```
openssl ec -inform PEM -outform DER -in ecdsa-secp256r1-key.pem -out ecdsa-secp256r1-key.der
openssl ec -inform PEM -outform DER -in ecdsa-secp384r1-key.pem -out ecdsa-secp384r1-key.der
openssl ec -inform PEM -outform DER -in ecdsa-secp521r1-key.pem -out ecdsa-secp521r1-key.der

openssl ec -inform PEM -outform DER -in ecdsa-secp256r1-key.pem -pubout -out ecdsa-secp256r1-pubkey.der
openssl ec -inform PEM -outform DER -in ecdsa-secp384r1-key.pem -pubout -out ecdsa-secp384r1-pubkey.der
openssl ec -inform PEM -outform DER -in ecdsa-secp521r1-key.pem -pubout -out ecdsa-secp521r1-pubkey.der
```

### Convert PEM cert file to DER file (IMPORTANT: use OpenSSL 1.x for generating DER files!!!)
```
openssl x509 -outform DER -in cacert.pem -out cacert.der
openssl x509 -outform DER -in ca2cert.pem -out ca2cert.der
openssl x509 -outform DER -in dsacert.pem -out dsacert.der
openssl x509 -outform DER -in dsa2048cert.pem -out dsa2048cert.der
openssl x509 -outform DER -in dsa3072cert.pem -out dsa3072cert.der
openssl x509 -outform DER -in rsacert.pem -out rsacert.der
openssl x509 -outform DER -in largersacert.pem -out largersacert.der
openssl x509 -outform DER -in expiredcert.pem -out expiredcert.der
openssl x509 -outform DER -in ecdsa-secp256r1-cert.pem -out ecdsa-secp256r1-cert.der
openssl x509 -outform DER -in ecdsa-secp384r1-cert.pem -out ecdsa-secp384r1-cert.der
openssl x509 -outform DER -in ecdsa-secp521r1-cert.pem -out ecdsa-secp521r1-cert.der
```


Certs for GOST keys (see above the instructions to configure GOST engine):
```
openssl x509 -outform DER -in gost2001cert.pem -out gost2001cert.der
openssl x509 -outform DER -in gost2012_256cert.pem -out gost2012_256cert.der
openssl x509 -outform DER -in gost2012_512cert.pem -out gost2012_512cert.der
```

### (optional) Convert PEM public key file to DER file
RSA key:
```
openssl rsa -inform PEM -outform DER -pubin -pubout -in lugh.key -out lugh.der
```

DSA key:
```
openssl dsa -inform PEM -outform DER -pubin -pubout -in lugh.key -out lugh.der
```

If you aren't sure if the public key is RSA or DSA, just run one of
the above commands, and the error messaging will make it clear :)

### (optional) Convert DER cert file to PEM file
```
openssl x509 -inform DER -outform PEM -in ca2cert.der -out ca2cert.pem
```

## Creating encrypted PEM or DER files
Converting an unencrypted PEM or DER file containing a private key to an encrypted
PEM or DER file containing the same private key but encrypted (the tests password
is `secret123`):
```
 openssl pkcs8 -in dsakey.pem -inform pem -out dsakey.p8-pem -outform pem -topk8
 openssl pkcs8 -in dsakey.der -inform der -out dsakey.p8-der -outform der -topk8
 openssl pkcs8 -in dsa2048key.pem -inform pem -out dsa2048key.p8-pem -outform pem -topk8
 openssl pkcs8 -in dsa2048key.der -inform der -out dsa2048key.p8-der -outform der -topk8
 openssl pkcs8 -in dsa3072key.pem -inform pem -out dsa3072key.p8-pem -outform pem -topk8
 openssl pkcs8 -in dsa3072key.der -inform der -out dsa3072key.p8-der -outform der -topk8
 openssl pkcs8 -in rsakey.pem -inform pem -out rsakey.p8-pem -outform pem -topk8
 openssl pkcs8 -in rsakey.der -inform der -out rsakey.p8-der -outform der -topk8

 openssl pkcs8 -in expiredkey.pem -inform pem -out expiredkey.p8-pem -outform pem -topk8
 openssl pkcs8 -in expiredkey.der -inform der -out expiredkey.p8-der -outform der -topk8

 openssl pkcs8 -in largersakey.pem -inform pem -out largersakey.p8-pem -outform pem -topk8
 openssl pkcs8 -in largersakey.der -inform der -out largersakey.p8-der -outform der -topk8
 openssl pkcs8 -in ecdsa-secp256r1-key.der -inform der -out ecdsa-secp256r1-key.p8-der -outform der -topk8
 openssl pkcs8 -in ecdsa-secp256r1-key.der -inform der -out ecdsa-secp256r1-key.p8-pem -outform pem -topk8
 openssl pkcs8 -in ecdsa-secp384r1-key.der -inform der -out ecdsa-secp384r1-key.p8-der -outform der -topk8
 openssl pkcs8 -in ecdsa-secp384r1-key.der -inform der -out ecdsa-secp384r1-key.p8-pem -outform pem -topk8
 openssl pkcs8 -in ecdsa-secp521r1-key.der -inform der -out ecdsa-secp521r1-key.p8-der -outform der -topk8
 openssl pkcs8 -in ecdsa-secp521r1-key.der -inform der -out ecdsa-secp521r1-key.p8-pem -outform pem -topk8
```



GOST keys (see above the instructions to configure GOST engine):
```
OPENSSL_CONF=./openssl.cnf openssl pkcs8 -in gost2001key.pem -inform pem -out gost2001key.p8-pem -outform pem -topk8
OPENSSL_CONF=./openssl.cnf openssl pkcs8 -in gost2012_256key.pem -inform pem -out gost2012_256key.p8-pem -outform pem -topk8
OPENSSL_CONF=./openssl.cnf openssl pkcs8 -in gost2012_512key.pem -inform pem -out gost2012_512key.p8-pem -outform pem -topk8
```

## Creating PKCS12 private keys
NSS is unfriendly towards standalone private keys. This procedure helps convert private
keys into PKCS12 form that is suitable for not only NSS but all crypto engines (the tests
password is `secret123`):

```
cat cakey.pem cacert.pem  > allcakey.pem
openssl pkcs12 -export -in allcakey.pem -name CARsaKey -out cakey.p12
rm allcakey.pem

cat ca2key.pem ca2cert.pem cacert.pem  > allca2key.pem
openssl pkcs12 -export -in allca2key.pem -name CA2RsaKey -out ca2key.p12
rm allca2key.pem

cat dsakey.pem dsacert.pem ca2cert.pem cacert.pem > alldsa.pem
openssl pkcs12 -export -in alldsa.pem -name dsakey -out dsakey.p12

cat dsa2048key.pem dsa2048cert.pem ca2cert.pem cacert.pem > alldsa2048.pem
openssl pkcs12 -export -in alldsa2048.pem -name TestDsa2048Key -out dsa2048key.p12

cat dsa3072key.pem dsa3072cert.pem ca2cert.pem cacert.pem > alldsa3072.pem
openssl pkcs12 -export -in alldsa3072.pem -name TestDsa3072Key -out dsa3072key.p12

cat rsakey.pem rsacert.pem ca2cert.pem cacert.pem > allrsa.pem
openssl pkcs12 -export -in allrsa.pem -name TestRsaKey -out rsakey.p12

cat largersakey.pem largersacert.pem ca2cert.pem cacert.pem > alllargersa.pem
openssl pkcs12 -export -in alllargersa.pem -name largersakey -out largersakey.p12

cat expiredkey.pem expiredcert.pem ca2cert.pem cacert.pem > allexpired.pem
openssl pkcs12 -export -in allexpired.pem -name TestExpiredRsaKey -out expiredkey.p12

cat ec-prime256v1-key.pem ec-prime256v1-cert.pem ca2cert.pem cacert.pem > all-ec-prime256v1.pem
openssl pkcs12 -export -in all-ec-prime256v1.pem -name TestEcdsaSecp256r1Key -out ec-prime256v1-key.p12
rm all-ec-prime256v1.pem

cat ec-prime256v1-second-key.pem ec-prime256v1-second-cert.pem ca2cert.pem cacert.pem > all-ec-prime256v1-second.pem
openssl pkcs12 -export -in all-ec-prime256v1-second.pem -name TestEcdsaSecp256r1Key -out ec-prime256v1-second-key.p12
rm all-ec-prime256v1-second.pem

cat ecdsa-secp256r1-key.pem ecdsa-secp256r1-cert.pem ca2cert.pem cacert.pem > all-ecdsa-secp256r1.pem
openssl pkcs12 -export -in all-ecdsa-secp256r1.pem -name TestEcdsaSecp256r1Key -out ecdsa-secp256r1-key.p12
rm all-ecdsa-secp256r1.pem

cat ecdsa-secp256r1-second-key.pem ecdsa-secp256r1-second-cert.pem ca2cert.pem cacert.pem > all-ecdsa-secp256r1-second.pem
openssl pkcs12 -export -in all-ecdsa-secp256r1-second.pem -name TestEcdsaSecp256r1Key -out ecdsa-secp256r1-second-key.p12
rm all-ecdsa-secp256r1-second.pem


cat ecdsa-secp384r1-key.pem ecdsa-secp384r1-cert.pem ca2cert.pem cacert.pem > all-ecdsa-secp384r1.pem
openssl pkcs12 -export -in all-ecdsa-secp384r1.pem -name TestEcdsaSecp384r1Key -out ecdsa-secp384r1-key.p12
rm all-ecdsa-secp384r1.pem

cat ecdsa-secp521r1-key.pem ecdsa-secp521r1-cert.pem ca2cert.pem cacert.pem > all-ecdsa-secp521r1.pem
openssl pkcs12 -export -in all-ecdsa-secp521r1.pem -name TestEcdsaSecp521r1Key -out ecdsa-secp521r1-key.p12
rm all-ecdsa-secp521r1.pem
```

GOST keys (see above the instructions to configure GOST engine):
```
cat gost2001key.pem gost2001cert.pem ca2cert.pem cacert.pem > all-gost2001.pem
OPENSSL_CONF=./openssl.cnf openssl pkcs12 -export -in all-gost2001.pem -name TestGost2001_Key -out gost2001key.p12
rm all-gost2001.pem

cat gost2012_256key.pem gost2012_256cert.pem ca2cert.pem cacert.pem > all-gost2012_256.pem
OPENSSL_CONF=./openssl.cnf openssl pkcs12 -export -in all-gost2012_256.pem -name TestGost2012_256Key -out gost2012_256key.p12
rm all-gost2012_256.pem

cat gost2012_512key.pem gost2012_512cert.pem ca2cert.pem cacert.pem > all-gost2012_512.pem
OPENSSL_CONF=./openssl.cnf openssl pkcs12 -export -in all-gost2012_512.pem -name TestGost2012_512Key -out gost2012_512key.p12
rm all-gost2012_512.pem
```

### Creating self-signed cert for DSA/RSA private keys and loading it into NSS store
The following process takes a DSA/RSA private key in PEM or DER format and
creates a PKCS12 file containing the private key, and a self-signed
certificate with the corresponding public key.

```
# first convert key file to PEM format, if not already in that format
openssl <dsa|rsa> -inform der -outform pem -in key.der -out key.pem

# answer questions at the prompt
# Note: use a unique subject (=issuer) for each self-signed cert you
# create (since there is no way to specify serial # using the command
# below)
openssl req -new -keyform <der|pem> -key key.<der|pem> -x509 -sha1 -days 999999 -outform pem -out cert.pem

# now using the cert and key in PEM format, conver them to a PKCS12 file
# enter some password on prompt
openssl pkcs12 -export -in cert.pem -inkey key.pem -name <nickname> -out keycert.p12

# This pkcs12 file can be used directly on the xmlsec command line, or
# can be pre-loaded into the crypto engine database (if any).

# In the case of NSS, you can pre-load the key using pk12util.
# The key and cert will have the nickname "nickname" (used in above step)
pk12util -d <nss_config_dir> -i keycert.p12
```

### Creating certs chain for DSA/RSA private keys and loading it into NSS store
The following process takes a DSA/RSA private key in PEM or DER format
plus all certs in the chain and creates a PKCS12 file containing the private key
and certs chain.

```
# first convert key file to PEM format, if not already in that format
openssl <dsa|rsa> -inform der -outform pem -in key.der -out key.pem

# convert all cert files to PEM format, if not already in that format
openssl x509 -inform der -outform pem -in cert.der -out cert.pem

# concatenate all cert.pem files created above to 1 file - allcerts.pem
cat keycert.pem cert1.pem cert2.pem  .... > allcerts.pem

# now using the certs and key in PEM format, conver them to a PKCS12 file
# enter some password on prompt
openssl pkcs12 -export -in allcerts.pem -inkey key.pem \
    -name <nickname of key & keycert>
[-caname <nickname of cert1> -caname <nickname of cert2>.... ]
-out keycert.p12

# This pkcs12 file can be used directly on the xmlsec command line, or
# can be pre-loaded into the crypto engine database (if any).

# In the case of NSS, you can pre-load the key using pk12util.
# The key and certs will have the nickname "nickname"
# (used in above step)
pk12util -d <nss_config_dir> -i keycert.p12
```

## Add Crypto Service Provider (CSP) for Windows
On Windows, one needs to specify Crypto Service Provider (CSP) in the pkcs12 file
to ensure it is loaded correctly to be used with SHA2 algorithms. Worse, the CSP is
different for XP and older versions.

```
cat rsakey.pem rsacert.pem ca2cert.pem cacert.pem > allrsa.pem
openssl pkcs12 -export -in allrsa.pem -name TestRsaKey -out rsakey-winxp.p12 -CSP "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)"
openssl pkcs12 -export -in allrsa.pem -name TestRsaKey -out rsakey-win.p12 -CSP "Microsoft Enhanced RSA and AES Cryptographic Provider"
rm allrsa.pem

cat largersakey.pem largersacert.pem ca2cert.pem cacert.pem > alllargersa.pem
openssl pkcs12 -export -in alllargersa.pem -name largersakey -out largersakey-winxp.p12 -CSP "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)"
openssl pkcs12 -export -in alllargersa.pem -name largersakey -out largersakey-win.p12 -CSP "Microsoft Enhanced RSA and AES Cryptographic Provider"
rm alllargersa.pem

cat dsakey.pem dsacert.pem ca2cert.pem cacert.pem > alldsa.pem
openssl pkcs12 -export -in alldsa.pem -name dsakey -out dsakey-win.p12 -CSP "Microsoft Enhanced RSA and AES Cryptographic Provider"
rm alldsa.pem

cat dsa2048key.pem dsa2048cert.pem ca2cert.pem cacert.pem > alldsa2048.pem
openssl pkcs12 -export -in alldsa2048.pem -name TestDsa2048Key -out dsa2048key-win.p12 -CSP "Microsoft Enhanced RSA and AES Cryptographic Provider"
rm alldsa2048.pem

cat dsa3072key.pem dsa3072cert.pem ca2cert.pem cacert.pem > alldsa3072.pem
openssl pkcs12 -export -in alldsa3072.pem -name TestDsa3072Key -out dsa3072key-win.p12 -CSP "Microsoft Enhanced RSA and AES Cryptographic Provider"
rm alldsa3072.pem


cat expiredkey.pem expiredcert.pem ca2cert.pem cacert.pem > allexpired.pem
openssl pkcs12 -export -in allexpired.pem -name TestExpiredRsaKey -out expiredkey-win.p12 -CSP "Microsoft Enhanced RSA and AES Cryptographic Provider"
rm allexpired.pem
```

## Convert DER private keys for GCrypt to understand
GCrypt doesn't have its own parser for DER/PEM format and the one implemented in xmlsec-gcrypt is pretty basic.
Thus, we need to convert DER private keys generated by modern OpenSSL to the original / traditional format:

``
openssl rsa -inform DER -outform DER -traditional -in input-priv-key.der  -out output-priv-key.der
``

To view the results, use the following command:

``
openssl asn1parse -inform DER -in some-priv-key.der
``
