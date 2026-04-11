# Verifying and decrypting documents

## Overview

The XML Security Library verifies signatures or decrypts data by
processing the signed/encrypted XML document, finding the required
key(s) in the keys manager or in the signature/encryption context,
performing the necessary cryptographic operations, and returning the
verification results or the decrypted data.

### Figure: The verification or decryption processing model
![The verification or decryption processing model](images/verif-dec-model.png)

## Verifying a signed document

A typical signature verification process includes the following steps:
- Load the signed XML file and select the
  [dsig:Signature](http://www.w3.org/TR/xmldsig-core/#sec-Signature)
  node.
- Create a signature context using the
  [xmlSecDSigCtxCreate](../api/xmlsec_core_xmldsig.md#xmlsecdsigctxcreate)
  function.
- Load the verification key(s), X509 certificates, etc. into the
  [keys manager](../api/xmlsec_core_keysmngr.md#xmlseckeysmngrcreate)
  or set the key in the signature context (the `signKey` member of the
  [xmlSecDSigCtx](../api/xmlsec_core_xmldsig.md#xmlsecdsigctxcreate)
  structure).
- Verify the signature by calling the
  [xmlSecDSigCtxVerify](../api/xmlsec_core_xmldsig.md#xmlsecdsigctxverify)
  function.
- Check the returned value and the verification status (the `status`
  member of the
  [xmlSecDSigCtx](../api/xmlsec_core_xmldsig.md#xmlsecdsigctxcreate)
  structure).
- Perform additional checks to ensure the signature is valid (for
    example, validate References and Transforms to ensure that the
    expected data was actually signed).
- Destroy the signature context using the
  [xmlSecDSigCtxDestroy](../api/xmlsec_core_xmldsig.md#xmlsecdsigctxdestroy)
  function.


### Example: Verifying a document

```c
/**
 * @brief Verifies XML signature in a file using a public key.
 * @details Verifies XML signature in #xml_file using public key from #key_file.
 * @param xml_file the signed XML file name.
 * @param key_file the PEM public key file name.
 * @return 0 on success or a negative value if an error occurs.
 */
int
verify_file(const char* xml_file, const char* key_file) {
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    int res = -1;

    assert(xml_file);
    assert(key_file);

    /* load file */
    doc = xmlReadFile(xml_file, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET | XML_PARSE_NOENT);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", xml_file);
        goto done;
    }

    /* find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
    if(node == NULL) {
        fprintf(stderr, "Error: start node not found in \"%s\"\n", xml_file);
        goto done;
    }

    /* create signature context, we don't need keys manager in this example */
    dsigCtx = xmlSecDSigCtxCreate(NULL);
    if(dsigCtx == NULL) {
        fprintf(stderr,"Error: failed to create signature context\n");
        goto done;
    }

    /* load public or private key */
    dsigCtx->signKey = xmlSecCryptoAppKeyLoadEx(key_file, xmlSecKeyDataTypePrivate | xmlSecKeyDataTypePublic, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
    if(dsigCtx->signKey == NULL) {
        fprintf(stderr,"Error: failed to load public pem key from \"%s\"\n", key_file);
        goto done;
    }

    /* set the key name to the file name; this is only an example */
    if(xmlSecKeySetName(dsigCtx->signKey, BAD_CAST key_file) < 0) {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", key_file);
        goto done;
    }

    /* Verify signature */
    if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
        fprintf(stderr,"Error: signature verification failed\n");
        goto done;
    }

    /* verify results and print outcome to stdout */
    if(verify_signature_results(dsigCtx) == 0) {
        fprintf(stdout, "Signature is OK\n");
    } else {
        fprintf(stdout, "Signature is INVALID\n");
    }

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

/**
 * @brief Verifies XML signature results match expected data.
 * @details Verifies XML signature results to ensure that signature was applied
 * to the expected data.
 * @param dsigCtx the XMLDSig context
 * @return 0 on success or a negative value if an error occurs.
 */
int
verify_signature_results(xmlSecDSigCtxPtr dsigCtx) {
    xmlSecDSigReferenceCtxPtr dsigRefCtx;
    xmlSecTransformPtr transform;

    assert(dsigCtx);

    /* check that signature verification succeeded */
    if(dsigCtx->status != xmlSecDSigStatusSucceeded) {
        fprintf(stderr,"Error: Signature verification result is not SUCCESS\n");
        return(-1);
    }

    /* in this example we expect exactly ONE reference with URI="" and
    *  exactly ONE enveloped signature transform (i.e. the whole document is signed)*/
    if(xmlSecPtrListGetSize(&(dsigCtx->signedInfoReferences)) != 1) {
        fprintf(stderr,"Error: Exactly one Reference is expected\n");
        return(-1);
    }
    dsigRefCtx = (xmlSecDSigReferenceCtxPtr)xmlSecPtrListGetItem(&(dsigCtx->signedInfoReferences), 0);
    if((dsigRefCtx == NULL) || (dsigRefCtx->status != xmlSecDSigStatusSucceeded)) {
        fprintf(stderr,"Error: Reference verification result is not SUCCESS\n");
        return(-1);
    }

    /* check URI */
    if(!xmlStrEqual(dsigRefCtx->uri, BAD_CAST "")) {
        fprintf(stderr,"Error: Reference URI value doesn't match expected one\n");
        return(-1);
    }

    /* check transforms: we expect only one "enveloped signature" transform */
    transform = dsigRefCtx->transformCtx.first;
    if((transform == NULL) || (!xmlStrEqual(transform->id->name, xmlSecNameEnveloped))) {
        fprintf(stderr,"Error: First Transform name '%s' doesn't match expected '%s'\n", (transform != NULL ? transform->id->name : BAD_CAST "NULL"), xmlSecNameEnveloped);
        return(-1);
    }

    /* all other transforms should be inserted by XMLSec */
    transform = transform->next;
    while(transform != NULL) {
        if((transform->flags & XMLSEC_TRANSFORM_FLAGS_USER_SPECIFIED) != 0) {
            fprintf(stderr,"Error: Found unexpected Transform name '%s'\n", transform->id->name);
            return(-1);
        }
        transform = transform->next;
    }

    /* all good! */
    return(0);
}
```

[Full Program Listing](../examples/verify1.md)


## Decrypting an encrypted document

A typical decryption process includes the following steps:
- Load the encrypted XML file and select the
    [enc:EncryptedData](http://www.w3.org/TR/xmlenc-core/#sec-EncryptedData)
  node.
- Create an encryption context using the
  [xmlSecEncCtxCreate](../api/xmlsec_core_xmlenc.md#xmlsecencctxcreate)
  function.
- Load the decryption key(s), X509 certificates, etc. into the
  [keys manager](../api/xmlsec_core_keysmngr.md#xmlseckeysmngrcreate)
  or set the key in the encryption context (the `encKey` member of
  [xmlSecEncCtx](../api/xmlsec_core_xmlenc.md#xmlsecencctxcreate)
  structure).
- Decrypt the data by calling the
    [xmlSecEncCtxDecrypt](../api/xmlsec_core_xmlenc.md#xmlsecencctxdecrypt)
    function.
- Check the returned value to make sure there are no errors.
- Destroy the encryption context using the
  [xmlSecEncCtxDestroy](../api/xmlsec_core_xmlenc.md#xmlsecencctxdestroy)
  function.


### Example: Decrypting a document

```c

/**
 * @brief Decrypts an encrypted XML file using a DES key.
 * @details Decrypts the XML file #enc_file using DES key from #key_file and
 * prints results to stdout.
 * @param enc_file the encrypted XML  file name.
 * @param key_file the Triple DES key file.
 * @return 0 on success or a negative value if an error occurs.
 */
int
decrypt_file(const char* enc_file, const char* key_file) {
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecEncCtxPtr encCtx = NULL;
    int res = -1;

    assert(enc_file);
    assert(key_file);

    /* load template */
    doc = xmlReadFile(enc_file, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET | XML_PARSE_NOENT);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", enc_file);
        goto done;
    }

    /* find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeEncryptedData, xmlSecEncNs);
    if(node == NULL) {
        fprintf(stderr, "Error: start node not found in \"%s\"\n", enc_file);
        goto done;
    }

    /* create encryption context, we don't need keys manager in this example */
    encCtx = xmlSecEncCtxCreate(NULL);
    if(encCtx == NULL) {
        fprintf(stderr,"Error: failed to create encryption context\n");
        goto done;
    }

    /* load DES key */
    encCtx->encKey = xmlSecKeyReadBinaryFile(xmlSecKeyDataDesId, key_file);
    if(encCtx->encKey == NULL) {
        fprintf(stderr,"Error: failed to load des key from binary file \"%s\"\n", key_file);
        goto done;
    }

    /* set the key name to the file name; this is only an example */
    if(xmlSecKeySetName(encCtx->encKey, BAD_CAST key_file) < 0) {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", key_file);
        goto done;
    }

    /* decrypt the data */
    if((xmlSecEncCtxDecrypt(encCtx, node) < 0) || (encCtx->result == NULL)) {
        fprintf(stderr,"Error: decryption failed\n");
        goto done;
    }

    /* print decrypted data to stdout */
    if(encCtx->resultReplaced != 0) {
        fprintf(stdout, "Decrypted XML data:\n");
        xmlDocDump(stdout, doc);
    } else {
        fprintf(stdout, "Decrypted binary data (" XMLSEC_SIZE_FMT " bytes):\n",
            xmlSecBufferGetSize(encCtx->result));
        if(xmlSecBufferGetData(encCtx->result) != NULL) {
            fwrite(xmlSecBufferGetData(encCtx->result),
                  1,
                  xmlSecBufferGetSize(encCtx->result),
                  stdout);
        }
    }
    fprintf(stdout, "\n");

    /* success */
    res = 0;

done:
    /* cleanup */
    if(encCtx != NULL) {
        xmlSecEncCtxDestroy(encCtx);
    }

    if(doc != NULL) {
        xmlFreeDoc(doc);
    }
    return(res);
}
```

[Full Program Listing](../examples/decrypt1.md)

