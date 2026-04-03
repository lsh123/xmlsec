# Using X509 Certificates

## Overview

X509 certificate is one of many possible keys data object that can be associated with a key. Application may read and write X509 data from/to XML file. The X509 certificates management policies significantly vary from one crypto library to another. The examples in this chapter were tested with OpenSSL and they might be broken if anither crypto engine is used. Check API reference documentation for more specific information about your crypto engine.

## Signing data with X509 certificate

To sign a file using X509 certificate, an application need to associate the certificate (or certificates) with the private key using one of the following functions:
- [xmlSecOpenSSLAppKeyCertLoad](#xmlsecopensslappkeycertload) - loads certificate from a file and adds to the key;
- [xmlSecOpenSSLAppPkcs12Load](#xmlsecopensslapppkcs12load) - loads private key and all the certificates associated with it from a PKCS12 file;
- [xmlSecKeyAdoptData](#xmlseckeyadoptdata) - low level function to add key data (including X509 key data) to the key.
**Example: Loading private key and X509 certificate**
```
    /* load private key, assuming that there is not password */
    key = xmlSecCryptoAppKeyLoad(key_file, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
    if(key == NULL) {
        fprintf(stderr,"Error: failed to load private pem key from \"%s\"\n", key_file);
	goto done;
    }

    /* load certificate and add to the key */
    if(xmlSecCryptoAppKeyCertLoad(key, cert_file, xmlSecKeyDataFormatPem) < 0) {
        fprintf(stderr,"Error: failed to load pem certificate \"%s\"\n", cert_file);
	goto done;
    }
```
[Full program listing](#xmlsec-example-sign3)

Next step is to prepare signature template with <dsig:X509Data/> child of the <dsig:KeyInfo/> element. When XML Security Library finds this node in the template, it automatically creates <dsig:X509Certificate/> children of the <dsig:X509Data/> element and writes to result XML document all the certificates associated with the signature key.
**Example: Dynamicaly creating a signature template for signing document using X509 certificate**
```
    /* create signature template for RSA-SHA1 enveloped signature */
    signNode = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId,
				         xmlSecTransformRsaSha1Id, NULL);
    if(signNode == NULL) {
	fprintf(stderr, "Error: failed to create signature template\n");
	goto done;
    }

    /* add <dsig:Signature/> node to the doc */
    xmlAddChild(xmlDocGetRootElement(doc), signNode);

    /* add reference */
    refNode = xmlSecTmplSignatureAddReference(signNode, xmlSecTransformSha1Id,
					NULL, NULL, NULL);
    if(refNode == NULL) {
	fprintf(stderr, "Error: failed to add reference to signature template\n");
	goto done;
    }

    /* add enveloped transform */
    if(xmlSecTmplReferenceAddTransform(refNode, xmlSecTransformEnvelopedId) == NULL) {
	fprintf(stderr, "Error: failed to add enveloped transform to reference\n");
	goto done;
    }

    /* add <dsig:KeyInfo/> and <dsig:X509Data/> */
    keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
    if(keyInfoNode == NULL) {
	fprintf(stderr, "Error: failed to add key info\n");
	goto done;
    }

    if(xmlSecTmplKeyInfoAddX509Data(keyInfoNode) == NULL) {
	fprintf(stderr, "Error: failed to add X509Data node\n");
	goto done;
    }
```
[Full program listing](#xmlsec-example-sign3)

## Verifing document signed with X509 certificates

If the document is signed with an X509 certificate then the signature verification consist of two steps:
- Creating and verifing X509 certificates chain.
- Verifing signature itself using key exrtacted from a certificate verified on previous step.
Certificates chain is constructed from certificates in a way that each certificate in the chain is signed with previous one:
**Certificates chain**
```
Certificate A (signed with B) <- Certificate B (signed with C) <- ... <- Root Certificate (signed by itself)
```
At the end of the chain there is a "Root Certificate" which is signed by itself. There is no way to verify the validity of the root certificate and application have to "trust" it (another name for root certificates is "trusted" certificates).

Application can use [xmlSecCryptoAppKeysMngrCertLoad](#xmlseccryptoappkeysmngrcertload) function to load both "trusted" and "un-trusted" certificates. However, the selection of "trusted" certificates is very sensitive process and this function might be not implemented for some crypto engines. In this case, the "trusted" certificates list is loaded during initialization or specified in crypto engine configuration files. Check XML Security Library API reference for more details.
**Example: Loading trusted X509 certificate**
```
/**
 * load_trusted_certs:
 * @files:		the list of filenames.
 * @files_size:		the number of filenames in #files.
 *
 * Creates simple keys manager and load trusted certificates from PEM #files.
 * The caller is responsible for destroing returned keys manager using
 * @xmlSecKeysMngrDestroy.
 *
 * Returns the pointer to newly created keys manager or NULL if an error
 * occurs.
 */
xmlSecKeysMngrPtr
load_trusted_certs(char** files, int files_size) {
    xmlSecKeysMngrPtr mngr;
    int i;

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

    for(i = 0; i < files_size; ++i) {
	assert(files[i]);

	/* load trusted cert */
	if(xmlSecCryptoAppKeysMngrCertLoad(mngr, files[i], xmlSecKeyDataFormatPem, xmlSecKeyDataTypeTrusted) < 0) {
    	    fprintf(stderr,"Error: failed to load pem certificate from \"%s\"\n", files[i]);
	    xmlSecKeysMngrDestroy(mngr);
	    return(NULL);
	}
    }

    return(mngr);
}
```
[Full program listing](#xmlsec-example-verify3)

