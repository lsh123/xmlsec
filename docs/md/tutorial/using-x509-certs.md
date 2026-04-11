# Using X509 certificates

## Overview

An X509 certificate is one of many possible key data objects that can
be associated with a key. An application can read and write X509 data
to and from an XML file. X509 certificate management policies vary
significantly from one crypto library to another. Check the reference
documentation for the cryptographic library for details.

## Signing data with an X509 certificate

To sign a file using an X509 certificate, an application needs to
associate the certificate (or certificates) with the private key using
one of the following functions:

- [xmlSecOpenSSLAppKeyCertLoad](../api/xmlsec_openssl_app.md#xmlsecopensslappkeycertload):
  loads certificate from a file and adds to the key;
- [xmlSecOpenSSLAppPkcs12Load](../api/xmlsec_openssl_app.md#xmlsecopensslapppkcs12load):
  loads private key and all the certificates associated with it from
  a PKCS12 file;
- [xmlSecKeyAdoptData](../api/xmlsec_core_keys.md#xmlseckeyadoptdata):
    low-level function to add key data (including X509 key data) to the key.

### Example: Loading private key and X509 certificate

```c
    /* load private key, assuming that there is no password */
    dsigCtx->signKey = xmlSecCryptoAppKeyLoadEx(key_file,
        xmlSecKeyDataTypePrivate,
        xmlSecKeyDataFormatPem,
        NULL,
        NULL,
        NULL);
    if(dsigCtx->signKey == NULL) {
        fprintf(stderr,"Error: failed to load private pem key from \"%s\"\n", key_file);
        goto done;
    }

    /* load certificate and add to the key */
    if(xmlSecCryptoAppKeyCertLoad(dsigCtx->signKey, cert_file, xmlSecKeyDataFormatPem) < 0) {
        fprintf(stderr,"Error: failed to load pem certificate \"%s\"\n", cert_file);
        goto done;
    }

```
[Full program listing](../examples/sign3.md)

The next step is to add a
[dsig:X509Data](http://www.w3.org/TR/xmldsig-core/#sec-X509Data) node
to the
[dsig:KeyInfo](http://www.w3.org/TR/xmldsig-core/#sec-KeyInfo) element
in the signature template. When the XML Security Library finds this
node in the template, it automatically creates
[dsig:X509Certificate](http://www.w3.org/TR/xmldsig-core/#sec-X509Data)
child elements and writes all the certificates associated with the
signature key to the resulting XML document.

### Example: Dynamically creating a signature template with X509 data

```c
    /* add <dsig:KeyInfo/> and <dsig:X509Data/> */
    keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
    if(keyInfoNode == NULL) {
        fprintf(stderr, "Error: failed to add key info\n");
        goto done;
    }

    x509DataNode = xmlSecTmplKeyInfoAddX509Data(keyInfoNode);
    if(x509DataNode == NULL) {
        fprintf(stderr, "Error: failed to add X509Data node\n");
        goto done;
    }

    if(xmlSecTmplX509DataAddSubjectName(x509DataNode) == NULL) {
        fprintf(stderr, "Error: failed to add X509SubjectName node\n");
        goto done;
    }

    if(xmlSecTmplX509DataAddCertificate(x509DataNode) == NULL) {
        fprintf(stderr, "Error: failed to add X509Certificate node\n");
        goto done;
    }
```
[Full program listing](../examples/sign3.md)

## Verifying a document signed with X509 certificates

If a document is signed with an X509 certificate, signature
verification consists of two steps:
- Creating and verifying the X509 certificates
  [chain of trust](https://letsencrypt.org/certificates/).
- Verifying the signature itself using the key extracted from a
  certificate verified on the previous step.


### Example: Certificates chain of trust

```
Certificate A (signed with B) <- Certificate B (signed with C) <- ... <- Root Certificate (signed by itself)
```

At the end of the chain of trust, there is a trusted certificate (for
example, a "Root Certificate" that is signed by itself). The
"trusted" certificates are usually configured in the cryptographic
library or can be loaded by the XML Security Library.
For example, the
[xmlSecCryptoAppKeysMngrCertLoad](../api/xmlsec_core_app.md#xmlseccryptoappkeysmngrcertload)
function can be used to load both "trusted" and "untrusted"
certificates.

### Example: Loading trusted X509 certificate

```c
/**
 * @brief Creates a keys manager and loads trusted X.509 certificates.
 * @details Creates a simple keys manager and loads trusted certificates from PEM #files.
 * The caller is responsible for destroying returned keys manager using
 * #xmlSecKeysMngrDestroy.
 * @param files the list of filenames.
 * @param files_size the number of filenames in #files.
 * @return the pointer to newly created keys manager or NULL if an error
 * occurs.
 */
xmlSecKeysMngrPtr
load_trusted_certs(char** files, int files_size) {
    xmlSecKeysMngrPtr mngr;
    int ii;

    assert(files);
    assert(files_size > 0);

    /* create and initialize keys manager, we use a simple list based
     * keys manager, implement your own xmlSecKeysStore klass if you need
     * something more sophisticated
     */
    mngr = xmlSecKeysMngrCreate();
    if(mngr == NULL) {
        fprintf(stderr, "Error: failed to create keys manager.\n");
        return(NULL);
    }
    if(xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
        fprintf(stderr, "Error: failed to initialize keys manager.\n");
        xmlSecKeysMngrDestroy(mngr);
        return(NULL);
    }

    for(ii = 0; ii < files_size; ++ii) {
        assert(files[ii]);

        /* load trusted cert */
        if(xmlSecCryptoAppKeysMngrCertLoad(mngr, files[ii], xmlSecKeyDataFormatPem, xmlSecKeyDataTypeTrusted) < 0) {
            fprintf(stderr,"Error: failed to load pem certificate from \"%s\"\n", files[ii]);
            xmlSecKeysMngrDestroy(mngr);
            return(NULL);
        }
    }

    return(mngr);
}
```
[Full program listing](../examples/verify3.md)

