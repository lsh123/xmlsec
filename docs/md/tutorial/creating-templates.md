# Creating dynamic templates

## Overview

The XML Security Library uses templates to describe how and what data should be signed or encrypted. The template is a regular XML file. You can create templates in advance using your favorite XML files editor, load them from a file and use for creating signature or encrypting data. You can also create templates dynamicaly. The XML Security Library provides helper functions to quickly create dynamic templates inside your application.

## Creating dynamic signature templates

The signature template has structure similar to the XML Digital Signature structure as it is described in [specification](http://www.w3.org/TR/xmldsig-core) . The only difference is that some nodes (for example, [<dsig:DigestValue/>](http://www.w3.org/TR/xmldsig-core/#sec-DigestValue) or <SignatureValue/>) are empty. The XML Security Library sets the content of these nodes after doing necessary calculations.

**XML Digital Signature structure**

```xml
<dsig:Signature ID?>
    <dsig:SignedInfo>
        <dsig:CanonicalizationMethod Algorithm />
        <dsig:SignatureMethod Algorithm />
        (<dsig:Reference URI? >
    	    (<dsig:Transforms>
		(<dsig:Transform Algorithm />)+
	     </dsig:Transforms>)?
	    <dsig:DigestMethod Algorithm >
	    <dsig:DigestValue>
	</dsig:Reference>)+
    </dsig:SignedInfo>
    <dsig:SignatureValue>
    (<dsig:KeyInfo>
	<dsig:KeyName>?
	<dsig:KeyValue>?
	<dsig:RetrievalMethod>?
	<dsig:X509Data>?
	<dsig:PGPData>?
	<enc:EncryptedKey>?
	<enc:AgreementMethod>?
	<dsig:KeyName>?
	<dsig:RetrievalMethod>?
	<*>?
    </dsig:KeyInfo>)?
    (<dsig:Object ID?>)*
</dsig:Signature>
```

**Example: Creating dynamic signature template**

```c
/**
 * sign_file:
 * @xml_file:		the XML file name.
 * @key_file:		the PEM private key file name.
 *
 * Signs the #xml_file using private key from #key_file and dynamicaly
 * created enveloped signature template.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
sign_file(const char* xml_file, const char* key_file) {
    xmlDocPtr doc = NULL;
    xmlNodePtr signNode = NULL;
    xmlNodePtr refNode = NULL;
    xmlNodePtr keyInfoNode = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    int res = -1;

    assert(xml_file);
    assert(key_file);

    /* load doc file */
    doc = xmlParseFile(xml_file);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
	fprintf(stderr, "Error: unable to parse file \"%s\"\n", xml_file);
	goto done;
    }

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

    /* add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to put key name in the signed document */
    keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
    if(keyInfoNode == NULL) {
	fprintf(stderr, "Error: failed to add key info\n");
	goto done;
    }

    if(xmlSecTmplKeyInfoAddKeyName(keyInfoNode, NULL) == NULL) {
	fprintf(stderr, "Error: failed to add key name\n");
	goto done;
    }

    /* create signature context, we don't need keys manager in this example */
    dsigCtx = xmlSecDSigCtxCreate(NULL);
    if(dsigCtx == NULL) {
        fprintf(stderr,"Error: failed to create signature context\n");
	goto done;
    }

    /* load private key, assuming that there is not password */
    dsigCtx->signKey = xmlSecCryptoAppKeyLoad(key_file, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
    if(dsigCtx->signKey == NULL) {
        fprintf(stderr,"Error: failed to load private pem key from \"%s\"\n", key_file);
	goto done;
    }

    /* set key name to the file name, this is just an example! */
    if(xmlSecKeySetName(dsigCtx->signKey, key_file) < 0) {
    	fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", key_file);
	goto done;
    }

    /* sign the template */
    if(xmlSecDSigCtxSign(dsigCtx, signNode) < 0) {
        fprintf(stderr,"Error: signature failed\n");
	goto done;
    }

    /* print signed document to stdout */
    xmlDocDump(stdout, doc);

    /* success */
    res = 0;

done:
    /* cleanup */
    if(dsigCtx != NULL) {
	xmlSecDSigCtxDestroy(dsigCtx);
    }

    if(doc != NULL) {
	xmlFreeDoc(doc);
    }
    return(res);
}
```
[Full program listing](../examples/sign2.md)

## Creating dynamic encryption templates

The encryption template has structure similar to the XML Encryption structure as it is described in [specification](http://www.w3.org/TR/xmlenc-core) . The only difference is that some nodes (for example, [<enc:CipherValue/>](http://www.w3.org/TR/xmlenc-core/#sec-CipherData)) are empty. The XML Security Library sets the content of these nodes after doing necessary calculations.

**XML Encryption structure**

```xml
<enc:EncryptedData Id? Type? MimeType? Encoding?>
    <enc:EncryptionMethod Algorithm />?
    (<dsig:KeyInfo>
	<dsig:KeyName>?
	<dsig:KeyValue>?
	<dsig:RetrievalMethod>?
	<dsig:X509Data>?
	<dsig:PGPData>?
	<enc:EncryptedKey>?
	<enc:AgreementMethod>?
	<dsig:KeyName>?
	<dsig:RetrievalMethod>?
	<*>?
    </dsig:KeyInfo>)?
    <enc:CipherData>
	<enc:CipherValue>?
	<enc:CipherReference URI?>?
    </enc:CipherData>
    <enc:EncryptionProperties>?
</enc:EncryptedData>
```

**Example: Creating dynamic encrytion template**

```c
/**
 * encrypt_file:
 * @xml_file:		the encryption template file name.
 * @key_file:		the Triple DES key file.
 *
 * Encrypts #xml_file using a dynamicaly created template and DES key from
 * #key_file.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
encrypt_file(const char* xml_file, const char* key_file) {
    xmlDocPtr doc = NULL;
    xmlNodePtr encDataNode = NULL;
    xmlNodePtr keyInfoNode = NULL;
    xmlSecEncCtxPtr encCtx = NULL;
    int res = -1;

    assert(xml_file);
    assert(key_file);

    /* load template */
    doc = xmlParseFile(xml_file);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
	fprintf(stderr, "Error: unable to parse file \"%s\"\n", xml_file);
	goto done;
    }

    /* create encryption template to encrypt XML file and replace
     * its content with encryption result */
    encDataNode = xmlSecTmplEncDataCreate(doc, xmlSecTransformDes3CbcId,
				NULL, xmlSecTypeEncElement, NULL, NULL);
    if(encDataNode == NULL) {
	fprintf(stderr, "Error: failed to create encryption template\n");
	goto done;
    }

    /* we want to put encrypted data in the <enc:CipherValue/> node */
    if(xmlSecTmplEncDataEnsureCipherValue(encDataNode) == NULL) {
	fprintf(stderr, "Error: failed to add CipherValue node\n");
	goto done;
    }

    /* add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to put key name in the signed document */
    keyInfoNode = xmlSecTmplEncDataEnsureKeyInfo(encDataNode, NULL);
    if(keyInfoNode == NULL) {
	fprintf(stderr, "Error: failed to add key info\n");
	goto done;
    }

    if(xmlSecTmplKeyInfoAddKeyName(keyInfoNode, NULL) == NULL) {
	fprintf(stderr, "Error: failed to add key name\n");
	goto done;
    }

    /* create encryption context, we don't need keys manager in this example */
    encCtx = xmlSecEncCtxCreate(NULL);
    if(encCtx == NULL) {
        fprintf(stderr,"Error: failed to create encryption context\n");
	goto done;
    }

    /* load DES key, assuming that there is not password */
    encCtx->encKey = xmlSecKeyReadBinaryFile(xmlSecKeyDataDesId, key_file);
    if(encCtx->encKey == NULL) {
        fprintf(stderr,"Error: failed to load des key from binary file \"%s\"\n", key_file);
	goto done;
    }

    /* set key name to the file name, this is just an example! */
    if(xmlSecKeySetName(encCtx->encKey, key_file) < 0) {
    	fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", key_file);
	goto done;
    }

    /* encrypt the data */
    if(xmlSecEncCtxXmlEncrypt(encCtx, encDataNode, xmlDocGetRootElement(doc)) < 0) {
        fprintf(stderr,"Error: encryption failed\n");
	goto done;
    }

    /* we template is inserted in the doc */
    encDataNode = NULL;

    /* print encrypted data with document to stdout */
    xmlDocDump(stdout, doc);

    /* success */
    res = 0;

done:

    /* cleanup */
    if(encCtx != NULL) {
	xmlSecEncCtxDestroy(encCtx);
    }

    if(encDataNode != NULL) {
	xmlFreeNode(encDataNode);
    }

    if(doc != NULL) {
	xmlFreeDoc(doc);
    }
    return(res);
}
```
[Full program listing](../examples/encrypt2.md)

