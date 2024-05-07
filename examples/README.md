# XMLSec Library: Examples

This folder contains XML Security Library examples.

## Building examples

### Unixes
Just run the usual `make` command (assuming that xmlsec, libxml2, libxslt and
all other required libraries are already installed).

### Windows
- Add paths to include and library files for xmlsec, libxml2, libxslt and
openssl or nss to the environment variables INCLUDE and LIB.
- Edit `Makefile.w32` file and specify correct crypto engine (openssl or
nss for now). You can also specify necessary include and library paths
or change from static linking to using DLLs.
- Run `nmake -f Makefile.w32`

If something does not work, check the README file in the top level
`win32` folder for additional instructions.

## Examples

### sign1: signing with a template file

Files:
```
sign1.c             The source code
sign1-tmpl.xml      The template file for sign1 example
sign1-res.xml       The result of processing sign1_tmpl.xml by sign1.c
```

To run this example:
```
./sign1 sign1-tmpl.xml rsakey.pem
```

To sign a template file with `xmlsec1` command line utility (use `xmlsec` on Windows):
```
xmlsec1 sign --privkey rsakey.pem --output sign1.xml sign1-tmpl.xml
```

### sign2: signing a file with a dynamicaly created template

Files:
```
sign2.c             The source code
sign2-doc.xml       An example XML file for signing by sign2.c
sign2-res.xml       The result of signing sign2-doc.xml by sign2.c
```

To run this example:
```
./sign2 sign2-doc.xml rsakey.pem
```

### sign3: signing a file with a dynamicaly created template and an X509 certificate

Files:
```
sign3.c             The source code
sign3-doc.xml       An example XML file for signing by sign3.c
sign3-res.xml       The result of signing sign3-doc.xml by sign3.c
```

To run this example:
```
./sign3 sign3-doc.xml rsakey.pem rsacert.pem
```

### verify1: verifying a signed document with a public key

Files:
```
verify1.c           The source code
```

To run this example:
```
./verify1 sign1-res.xml rsapub.pem
./verify1 sign2-res.xml rsapub.pem
```

### verify2: verifying a signed document using keys manager

Files:
```
verify2.c           The source code
```

To run this example:
```
./verify2 sign1-res.xml rsapub.pem
./verify2 sign2-res.xml rsapub.pem
```

To verify a signed document with `xmlsec1` command line utility (use `xmlsec` on Windows):
```
xmlsec1 verify --pubkey rsapub.pem sign1-res.xml
xmlsec1 verify --pubkey rsapub.pem sign2-res.xml
```

### verify3: verifying a signed document using X509 certificate

Files:
```
verify3.c           The source code
```

To run this example:
```
./verify3 sign3-res.xml ca2cert.pem cacert.pem
```

To verify a signed document using X509 certificate with `xmlsec1` command line
utility (use `xmlsec` on Windows):
```
xmlsec1 verify --trusted ca2cert.pem --trusted cacert.pem sign3-res.xml
```

### verify4: verifying a simple SAML response using X509 certificate

Files:
```
verify4.c           The source code
verify4-tmpl.xml    An example template file with a simple SAML response for verify4 example
verify4-res.xml     Signed simple SAML response for verification by verify4.c
```

To run this example:
```
./verify4 verify4-res.xml ca2cert.pem cacert.pem
```

To verify a signed SAML response using X509 certificate with `xmlsec1` command line
utility (use `xmlsec` on Windows):
```
xmlsec1 verify --trusted ca2cert.pem --trusted cacert.pem verify4-res.xml
```

### encrypt1: encrypting binary data with a template file

Files:
```
encrypt1.c          The source code
encrypt1-res.xml    An example template file for encrypt1.c
encrypt1-tmpl.xml   The result of processing encrypt1_tmpl.xml by encrypt1.c
```

To run this example:
```
./encrypt1 encrypt1-tmpl.xml deskey.bin
```

To encrypt binary data with a template file with `xmlsec1` command line
utility (use `xmlsec` on Windows):
```
xmlsec1 encrypt --deskey deskey.bin  --binary-data binary.dat --output encrypt1.xml encrypt1-tmpl.xml
```

### encrypt2: encrypting XML file using a dynamicaly created template

Files:
```
encrypt2.c          The source code
encrypt2-doc.xml    An example XML file for encryption by encrypt2.c
encrypt2-res.xml    The result of encryptin encrypt2-doc.xml by encrypt2.c
```

To run this example:
```
./encrypt2 encrypt2-doc.xml deskey.bin
```

### encrypt3: encrypting XML file using a session DES key

Files:
```
encrypt3.c          The source code
encrypt3-doc.xml    An example XML file for encryption by encrypt3.c
encrypt3-res.xml    The result of encryptin encrypt3-doc.xml by encrypt3.c
```

To run this example:
```
./encrypt3 encrypt3-doc.xml rsakey.pem
```

### decrypt1: decrypting binary data using a single key

Files:
```
decrypt1.c          The source code
```

To run this example:
```
./decrypt1 encrypt1-res.xml deskey.bin
./decrypt1 encrypt2-res.xml deskey.bin
```

### decrypt2: decrypting binary data using keys manager

Files:
```
decrypt2.c          The source code
```

To run this example:
```
./decrypt2 encrypt1-res.xml deskey.bin
./decrypt2 encrypt2-res.xml deskey.bin
```

To decrypt binary data with `xmlsec1` command line utility (use `xmlsec` on Windows):
```
xmlsec1 decrypt --deskey deskey.bin encrypt1-res.xml
xmlsec1 decrypt --deskey deskey.bin encrypt2-res.xml
xmlsec1 decrypt --privkey rsakey.pem encrypt3-res.xml
```

### decrypt3: decrypting binary file using custom keys manager

Files:
```
decrypt3.c          The source code
```

To run this example:
```
./decrypt3 encrypt1-res.xml
./decrypt3 encrypt2-res.xml
./decrypt3 encrypt3-res.xml
```

### xmldsigverify: CGI script for signatures verifications

Files:
```
xmldsigverify.c     The source code
```

To run this example, install compiled xmldsigverify script into
your web server cgi-bin directory.

### Keys and certificates
```
cacert.pem          Root (trusted) certificate
ca2cert.pem         CA (trusted) certificate (signed with cacert.pem)
rsakey.pem          Private PEM key file
rsapub.pem          Public PEM key file
rsacert.pem         Certificate for rsakey.pem signed with ca2cert.pem
deskey.bin          A DES keys
```
