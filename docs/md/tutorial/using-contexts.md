# Using context objects


The [XML Digital Signature](http://www.w3.org/TR/xmldsig-core/) and the
[XML Encryption](http://www.w3.org/TR/xmlenc-core/) standards are very
flexible. Without the necessary checks, that flexibility can create
security vulnerabilities if an application does not ensure that the
standards are used properly.

For example, XPath and XSLT transforms can make it very difficult to
find out what exactly was signed by just looking at the transforms and
the input data. Many protocols based on the
[XML Digital Signature](http://www.w3.org/TR/xmldsig-core/)
and the [XML Encryption](http://www.w3.org/TR/xmlenc-core/) standards
restrict allowed key data types, allowed transforms, and input data:
a simple SAML Response should have only one
[dsig:Reference](http://www.w3.org/TR/xmldsig-core/#sec-Reference)
element with an empty or NULL URI attribute, and exactly one enveloped
transform.

The XML Security Library uses "context" objects (e.g.
[xmlSecDSigCtx](../api/xmlsec_core_xmldsig.md#xmlsecdsigctxcreate)
or
[xmlSecEncCtx](../api/xmlsec_core_xmlenc.md#xmlsecencctxcreate)) to
allow the application to control enabled features, and also to return
the additional information that the application MUST verify to confirm
that the signature or encryption meets application requirements.
The application typically creates a new "context" object for each
operation, sets the necessary options, and then uses the result
returned in the context after signing, verification, encryption, or
decryption.

## Example: SAML signature validation

```c
/**
 * @brief Verifies XML signature in #xml_file.
 * @param mngr the pointer to keys manager.
 * @param xml_file the signed XML file name.
 * @return 0 on success or a negative value if an error occurs.
 */
int
verify_file(xmlSecKeysMngrPtr mngr, const char* xml_file) {
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    int res = -1;

    assert(mngr);
    assert(xml_file);

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

    /* create signature context */
    dsigCtx = xmlSecDSigCtxCreate(mngr);
    if(dsigCtx == NULL) {
        fprintf(stderr,"Error: failed to create signature context\n");
        goto done;
    }

    /* limit the Reference URI attributes to empty or NULL */
    dsigCtx->enabledReferenceUris = xmlSecTransformUriTypeEmpty;

    /* limit allowed transforms for signature and reference processing */
    if((xmlSecDSigCtxEnableSignatureTransform(dsigCtx, xmlSecTransformInclC14NId) < 0) ||
       (xmlSecDSigCtxEnableSignatureTransform(dsigCtx, xmlSecTransformExclC14NId) < 0) ||
       (xmlSecDSigCtxEnableSignatureTransform(dsigCtx, xmlSecTransformSha1Id) < 0) ||
       (xmlSecDSigCtxEnableSignatureTransform(dsigCtx, xmlSecTransformRsaSha1Id) < 0)) {

        fprintf(stderr,"Error: failed to limit allowed signature transforms\n");
        goto done;
    }
    if((xmlSecDSigCtxEnableReferenceTransform(dsigCtx, xmlSecTransformInclC14NId) < 0) ||
       (xmlSecDSigCtxEnableReferenceTransform(dsigCtx, xmlSecTransformExclC14NId) < 0) ||
       (xmlSecDSigCtxEnableReferenceTransform(dsigCtx, xmlSecTransformSha1Id) < 0) ||
       (xmlSecDSigCtxEnableReferenceTransform(dsigCtx, xmlSecTransformEnvelopedId) < 0)) {

        fprintf(stderr,"Error: failed to limit allowed reference transforms\n");
        goto done;
    }

    /* in addition, limit possible key data to valid X509 certificates only */
    if(xmlSecPtrListAdd(&(dsigCtx->keyInfoReadCtx.enabledKeyData), BAD_CAST xmlSecKeyDataX509Id) < 0) {
        fprintf(stderr,"Error: failed to limit allowed key data\n");
        goto done;
    }
    if(xmlSecPtrListAdd(&(dsigCtx->keyInfoReadCtx.enabledKeyData), BAD_CAST xmlSecKeyDataNameId) < 0) {
        fprintf(stderr,"Error: failed to limit allowed key data\n");
        goto done;
    }

    /* Verify signature */
    if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
        fprintf(stderr,"Error: signature verify\n");
        goto done;
    }

    /* check that we have only one Reference */
    if((dsigCtx->status == xmlSecDSigStatusSucceeded) &&
        (xmlSecPtrListGetSize(&(dsigCtx->signedInfoReferences)) != 1)) {

        fprintf(stderr,"Error: only one reference is allowed\n");
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

```
[Full program listing](../examples/verify-saml.md)



