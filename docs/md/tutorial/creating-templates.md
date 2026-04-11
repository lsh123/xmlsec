# Creating dynamic templates

## Overview

The XML Security Library uses templates to describe how and what data
should be signed or encrypted. A template is a regular XML file. You
can create templates in advance using your favorite XML editor, load
them from a file, or create them dynamically. The XML Security Library
provides helper functions for creating dynamic templates within your
application.

## Creating dynamic signature templates

The signature template is similar in structure to
[XML Digital Signature](http://www.w3.org/TR/xmldsig-core). The only
difference is that some nodes (for example,
[dsig:DigestValue](http://www.w3.org/TR/xmldsig-core/#sec-DigestValue))
are empty. The XML Security Library fills these nodes after performing
the necessary cryptographic operations.

### XML Digital Signature template structure

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

###  Example: Creating dynamic signature template

```c
/**
 * @brief Adds enveloped signature template to the XML document.
 * @param doc the XML document.
 * @return pointer to the dsig:Signature node or NULL if an error occurs.
 */
xmlNodePtr
create_signature_template(xmlDocPtr doc){
    xmlNodePtr signNode = NULL;
    xmlNodePtr refNode = NULL;
    xmlNodePtr keyInfoNode = NULL;

    assert(doc);

    /* create signature template for RSA-SHA1 enveloped signature */
    signNode = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId, xmlSecTransformRsaSha1Id, NULL);
    if(signNode == NULL) {
        fprintf(stderr, "Error: failed to create signature template\n");
        return(NULL);
    }

    /* add <dsig:Signature/> node to the doc */
    xmlAddChild(xmlDocGetRootElement(doc), signNode);

    /* add <dsig:Reference/> node */
    refNode = xmlSecTmplSignatureAddReference(signNode, xmlSecTransformSha1Id, NULL, BAD_CAST "", NULL);
    if(refNode == NULL) {
        fprintf(stderr, "Error: failed to add reference to signature template\n");
        return(NULL);
    }

    /* adds <dsig:Transform/> node with enveloped transform */
    if(xmlSecTmplReferenceAddTransform(refNode, xmlSecTransformEnvelopedId) == NULL) {
        fprintf(stderr, "Error: failed to add enveloped transform to reference\n");
        return(NULL);
    }

    /* add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to put key name in the signed document */
    keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
    if(keyInfoNode == NULL) {
        fprintf(stderr, "Error: failed to add key info\n");
        return(NULL);
    }
    if(xmlSecTmplKeyInfoAddKeyName(keyInfoNode, NULL) == NULL) {
        fprintf(stderr, "Error: failed to add key name\n");
        return(NULL);
    }

    /* done */
    return(signNode);
}

```
[Full program listing](../examples/sign2.md)

## Creating dynamic encryption templates

The encryption template is similar in structure to
[XML Encryption](http://www.w3.org/TR/xmlenc-core). The only
difference is that some nodes (for example,
[enc:CipherValue](http://www.w3.org/TR/xmlenc-core/#sec-CipherData))
are empty. The XML Security Library fills these nodes after performing
the necessary cryptographic operations.

### XML Encryption structure

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

### Example: Creating a dynamic encryption template

```c
/**
 * @brief Creates encryption template to encrypt the XML file.
 * @param doc the XML document.
 * @return pointer to the <enc:EncryptedData/> node or NULL if an error occurs.
 */
xmlNodePtr
create_encryption_template(xmlDocPtr doc) {
    xmlNodePtr encDataNode = NULL;
    xmlNodePtr keyInfoNode = NULL;

    assert(doc);

    /* add <enc:EncryptedData/> node to encrypt XML file and replace its content with encryption result */
    encDataNode = xmlSecTmplEncDataCreate(doc, xmlSecTransformDes3CbcId, NULL, xmlSecTypeEncElement, NULL, NULL);
    if(encDataNode == NULL) {
        fprintf(stderr, "Error: failed to create encryption template\n");
        return(NULL);
    }

    /* add <enc:CipherValue/> node */
    if(xmlSecTmplEncDataEnsureCipherValue(encDataNode) == NULL) {
        fprintf(stderr, "Error: failed to add CipherValue node\n");
        return(NULL);
    }

    /* add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to put key name in the signed document */
    keyInfoNode = xmlSecTmplEncDataEnsureKeyInfo(encDataNode, NULL);
    if(keyInfoNode == NULL) {
        fprintf(stderr, "Error: failed to add key info\n");
        return(NULL);
    }
    if(xmlSecTmplKeyInfoAddKeyName(keyInfoNode, NULL) == NULL) {
        fprintf(stderr, "Error: failed to add key name\n");
        return(NULL);
    }

    /* done */
    return(encDataNode);
}
```
[Full program listing](../examples/encrypt2.md)

