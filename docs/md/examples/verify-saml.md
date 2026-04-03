# Verifying a signature with additional restrictions

Verifies an XML Digital Signature with additional restrictions (SAML-style).

## Source: `verify-saml.c`

```c
/**
 * XML Security Library example: Verifying a simple SAML response with X509 certificate
 *
 * Verifies a simple SAML response. In addition to regular verification
 * we ensure that the signature has only one <dsig:Reference/> element
 * with an empty or NULL URI attribute and one enveloped signature transform
 * as it is required by SAML specification.
 *
 * This example was developed and tested with OpenSSL crypto library. The
 * certificates management policies for another crypto library may break it.
 *
 * Usage:
 *      verify-saml <signed-file> <trusted-cert-pem-file1> [<trusted-cert-pem-file2> [...]]
 *
 * Example (success):
 *      ./verify-saml verify-saml-res.xml ca2cert.pem cacert.pem
 *
 * Example (failure):
 *      ./verify-saml verify-saml-bad-res.xml ca2cert.pem cacert.pem
 * In the same time, verify3 example successfully verifies this signature:
 *      ./verify3 verify-saml-bad-res.xml ca2cert.pem cacert.pem
 *
 * This is free software; see the Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#include <libxslt/security.h>
#endif /* XMLSEC_NO_XSLT */

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>

xmlSecKeysMngrPtr load_trusted_certs(char** files, int files_size);
int verify_file(xmlSecKeysMngrPtr mngr, const char* xml_file);
int verify_signature_results(xmlSecDSigCtxPtr dsigCtx);

int
main(int argc, char **argv) {
#ifndef XMLSEC_NO_XSLT
    xsltSecurityPrefsPtr xsltSecPrefs = NULL;
#endif /* XMLSEC_NO_XSLT */
    xmlSecKeysMngrPtr mngr;

    assert(argv);

    if(argc < 3) {
        fprintf(stderr, "Error: wrong number of arguments.\n");
        fprintf(stderr, "Usage: %s <xml-file> <cert-file1> [<cert-file2> [...]]\n", argv[0]);
        return(1);
    }

    /* Init libxml and libxslt libraries */
    xmlInitParser();
    LIBXML_TEST_VERSION

    /* Init libxslt */
#ifndef XMLSEC_NO_XSLT
    /* disable everything */
    xsltSecPrefs = xsltNewSecurityPrefs();
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_FILE,        xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_FILE,       xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_NETWORK,     xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_NETWORK,    xsltSecurityForbid);
    xsltSetDefaultSecurityPrefs(xsltSecPrefs);
#endif /* XMLSEC_NO_XSLT */

    /* Init xmlsec library */
    if(xmlSecInit() < 0) {
        fprintf(stderr, "Error: xmlsec initialization failed.\n");
        return(-1);
    }

    /* Check loaded library version */
    if(xmlSecCheckVersion() != 1) {
        fprintf(stderr, "Error: loaded xmlsec library version is not compatible.\n");
        return(-1);
    }

    /* Load default crypto engine if we are supporting dynamic
     * loading for xmlsec-crypto libraries. Use the crypto library
     * name ("openssl", "nss", etc.) to load corresponding
     * xmlsec-crypto library.
     */
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if(xmlSecCryptoDLLoadLibrary(NULL) < 0) {
        fprintf(stderr, "Error: unable to load default xmlsec-crypto library. Make sure\n"
                        "that you have it installed and check shared libraries path\n"
                        "(LD_LIBRARY_PATH and/or LTDL_LIBRARY_PATH) environment variables.\n");
        return(-1);
    }
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

    /* Init crypto library */
    if(xmlSecCryptoAppInit(NULL) < 0) {
        fprintf(stderr, "Error: crypto initialization failed.\n");
        return(-1);
    }

    /* Init xmlsec-crypto library */
    if(xmlSecCryptoInit() < 0) {
        fprintf(stderr, "Error: xmlsec-crypto initialization failed.\n");
        return(-1);
    }

    /* create keys manager and load trusted certificates */
    mngr = load_trusted_certs(&(argv[2]), argc - 2);
    if(mngr == NULL) {
        return(-1);
    }

    /* verify file */
    if(verify_file(mngr, argv[1]) < 0) {
        xmlSecKeysMngrDestroy(mngr);
        return(-1);
    }

    /* destroy keys manager */
    xmlSecKeysMngrDestroy(mngr);

    /* Shutdown xmlsec-crypto library */
    xmlSecCryptoShutdown();

    /* Shutdown crypto library */
    xmlSecCryptoAppShutdown();

    /* Shutdown xmlsec library */
    xmlSecShutdown();

    /* Shutdown libxslt/libxml */
#ifndef XMLSEC_NO_XSLT
    xsltFreeSecurityPrefs(xsltSecPrefs);
    xsltCleanupGlobals();
#endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();

    return(0);
}

/**
 * load_trusted_certs:
 * @files:              the list of filenames.
 * @files_size:         the number of filenames in #files.
 *
 * Creates simple keys manager and load trusted certificates from PEM #files.
 * The caller is responsible for destroying returned keys manager using
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

/**
 * verify_file:
 * @mngr:               the pointer to keys manager.
 * @xml_file:           the signed XML file name.
 *
 * Verifies XML signature in #xml_file.
 *
 * Returns 0 on success or a negative value if an error occurs.
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

    /* verif results and print outcome to stdout */
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
 * verify_signature_results:
 * @dsigCtx:            the XMLDSig context
 *
 * Verifies XML signature results to ensure that signature was applied
 * to the expected data.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
verify_signature_results(xmlSecDSigCtxPtr dsigCtx) {
    xmlSecDSigReferenceCtxPtr dsigRefCtx;
    xmlSecTransformPtr transform;

    assert(dsigCtx);

    /* check that signature verification succeeded */
    if(dsigCtx->status != xmlSecDSigStatusSucceeded) {
        fprintf(stderr,"Error: Signature verificaton result is not SUCCESS\n");
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

## Valid Template: `verify-saml-tmpl.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!--
XML Security Library example: A simple SAML response template (verify-saml example).

Sign it using the following command (replace __ with double dashes):

 ../apps/xmlsec sign __privkey:MyKey rsakey.pem,rsacert.pem __output verify-saml-res.xml verify-saml-tmpl.xml
-->
<Response xmlns="urn:oasis:names:tc:SAML:1.0:protocol" xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" IssueInstant="2002-04-18T16:56:54Z" MajorVersion="1" MinorVersion="0" Recipient="https://shire.target.com" ResponseID="7ddc31-ed4a03d703-FB24AD27D96135B68C99FB9AACFE2FFC">
  <dsig:Signature xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
    <dsig:SignedInfo>
      <dsig:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <dsig:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <dsig:Reference URI="">
        <dsig:Transforms>
          <dsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </dsig:Transforms>
        <dsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <dsig:DigestValue/>
      </dsig:Reference>
    </dsig:SignedInfo>
    <dsig:SignatureValue/>
    <dsig:KeyInfo>
      <dsig:KeyName>MyKey</dsig:KeyName>
      <dsig:X509Data/>
    </dsig:KeyInfo>
  </dsig:Signature>
  <Status>
    <StatusCode Value="samlp:Success"/>
  </Status>
  <Assertion xmlns="urn:oasis:names:tc:SAML:1.0:assertion" AssertionID="7ddc31-ed4a03d735-FB24AD27D96135B68C99FB9AACFE2FFC" IssueInstant="2002-04-18T16:56:54Z" Issuer="hs.osu.edu" MajorVersion="1" MinorVersion="0">
    <Conditions NotBefore="2002-04-18T16:56:54Z" NotOnOrAfter="2002-04-18T17:01:54Z">
      <AudienceRestrictionCondition>
        <Audience>http://middleware.internet2.edu/shibboleth/clubs/clubshib/1.0/</Audience>
      </AudienceRestrictionCondition>
    </Conditions>
    <AuthenticationStatement AuthenticationInstant="2002-04-18T16:56:53Z" AuthenticationMethod="urn:mace:shibboleth:authmethod">
      <Subject>
        <NameIdentifier Format="urn:mace:shibboleth:1.0:handle" NameQualifier="osu.edu">foo</NameIdentifier>
        <SubjectConfirmation>
          <ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:Bearer</ConfirmationMethod>
        </SubjectConfirmation>
      </Subject>
      <SubjectLocality IPAddress="127.0.0.1"/>
      <AuthorityBinding AuthorityKind="samlp:AttributeQuery" Binding="urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding" Location="https://aa.osu.edu/"/>
    </AuthenticationStatement>
  </Assertion>
</Response>
```

## Valid Result: `verify-saml-res.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!--
XML Security Library example: A simple SAML response template (verify-saml example).

Sign it using the following command (replace __ with double dashes):

 ../apps/xmlsec sign __privkey:MyKey rsakey.pem,rsacert.pem __output verify-saml-res.xml verify-saml-tmpl.xml
-->
<Response xmlns="urn:oasis:names:tc:SAML:1.0:protocol" xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" IssueInstant="2002-04-18T16:56:54Z" MajorVersion="1" MinorVersion="0" Recipient="https://shire.target.com" ResponseID="7ddc31-ed4a03d703-FB24AD27D96135B68C99FB9AACFE2FFC">
  <dsig:Signature xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
    <dsig:SignedInfo>
      <dsig:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <dsig:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <dsig:Reference URI="">
        <dsig:Transforms>
          <dsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </dsig:Transforms>
        <dsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <dsig:DigestValue>t1nvDq1bZXEhBIXc/DHcqIrjRyI=</dsig:DigestValue>
      </dsig:Reference>
    </dsig:SignedInfo>
    <dsig:SignatureValue>cj28Qr33wTqwHJzpI+7Mth7HUTr9MKACSH4x/1/AO64FEGiQRoOBB8XuUHZ8tzkP
Azy8FwoZE/Jv5d/0N3ru4Q==</dsig:SignatureValue>
    <dsig:KeyInfo>
      <dsig:KeyName>MyKey</dsig:KeyName>
      <dsig:X509Data>
<dsig:X509Certificate>MIIDpzCCA1GgAwIBAgIJAK+ii7kzrdqvMA0GCSqGSIb3DQEBBQUAMIGcMQswCQYD
VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTE9MDsGA1UEChM0WE1MIFNlY3Vy
aXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20veG1sc2VjKTEWMBQG
A1UEAxMNQWxla3NleSBTYW5pbjEhMB8GCSqGSIb3DQEJARYSeG1sc2VjQGFsZWtz
ZXkuY29tMCAXDTE0MDUyMzE3NTUzNFoYDzIxMTQwNDI5MTc1NTM0WjCBxzELMAkG
A1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExPTA7BgNVBAoTNFhNTCBTZWN1
cml0eSBMaWJyYXJ5IChodHRwOi8vd3d3LmFsZWtzZXkuY29tL3htbHNlYykxKTAn
BgNVBAsTIFRlc3QgVGhpcmQgTGV2ZWwgUlNBIENlcnRpZmljYXRlMRYwFAYDVQQD
Ew1BbGVrc2V5IFNhbmluMSEwHwYJKoZIhvcNAQkBFhJ4bWxzZWNAYWxla3NleS5j
b20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEA09BtD3aeVt6DVDkk0dI7Vh7Ljqdn
sYmW0tbDVxxK+nume+Z9Sb4znbUKkWl+vgQATdRUEyhT2P+Gqrd0UBzYfQIDAQAB
o4IBRTCCAUEwDAYDVR0TBAUwAwEB/zAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBH
ZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFNf0xkZ3zjcEI60pVPuwDqTM
QygZMIHjBgNVHSMEgdswgdiAFP7k7FMk8JWVxxC14US1XTllWuN+oYG0pIGxMIGu
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTE9MDsGA1UEChM0WE1M
IFNlY3VyaXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20veG1sc2Vj
KTEQMA4GA1UECxMHUm9vdCBDQTEWMBQGA1UEAxMNQWxla3NleSBTYW5pbjEhMB8G
CSqGSIb3DQEJARYSeG1sc2VjQGFsZWtzZXkuY29tggkAr6KLuTOt2q0wDQYJKoZI
hvcNAQEFBQADQQAOXBj0yICp1RmHXqnUlsppryLCW3pKBD1dkb4HWarO7RjA1yJJ
fBjXssrERn05kpBcrRfzou4r3DCgQFPhjxga
</dsig:X509Certificate>
</dsig:X509Data>
    </dsig:KeyInfo>
  </dsig:Signature>
  <Status>
    <StatusCode Value="samlp:Success"/>
  </Status>
  <Assertion xmlns="urn:oasis:names:tc:SAML:1.0:assertion" AssertionID="7ddc31-ed4a03d735-FB24AD27D96135B68C99FB9AACFE2FFC" IssueInstant="2002-04-18T16:56:54Z" Issuer="hs.osu.edu" MajorVersion="1" MinorVersion="0">
    <Conditions NotBefore="2002-04-18T16:56:54Z" NotOnOrAfter="2002-04-18T17:01:54Z">
      <AudienceRestrictionCondition>
        <Audience>http://middleware.internet2.edu/shibboleth/clubs/clubshib/1.0/</Audience>
      </AudienceRestrictionCondition>
    </Conditions>
    <AuthenticationStatement AuthenticationInstant="2002-04-18T16:56:53Z" AuthenticationMethod="urn:mace:shibboleth:authmethod">
      <Subject>
        <NameIdentifier Format="urn:mace:shibboleth:1.0:handle" NameQualifier="osu.edu">foo</NameIdentifier>
        <SubjectConfirmation>
          <ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:Bearer</ConfirmationMethod>
        </SubjectConfirmation>
      </Subject>
      <SubjectLocality IPAddress="127.0.0.1"/>
      <AuthorityBinding AuthorityKind="samlp:AttributeQuery" Binding="urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding" Location="https://aa.osu.edu/"/>
    </AuthenticationStatement>
  </Assertion>
</Response>
```

## Invalid Template: `verify-saml-bad-tmpl.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!--
XML Security Library example: A simple bad SAML response template (verify-saml example).

Sign it using the following command (replace __ with double dashes):

 $ xmlsec1 sign __privkey:MyKey rsakey.pem,rsacert.pem __output verify-saml-bad-res.xml verify-saml-bad-tmpl.xml
-->
<Response xmlns="urn:oasis:names:tc:SAML:1.0:protocol" xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" IssueInstant="2002-04-18T16:56:54Z" MajorVersion="1" MinorVersion="0" Recipient="https://shire.target.com" ResponseID="7ddc31-ed4a03d703-FB24AD27D96135B68C99FB9AACFE2FFC">
  <dsig:Signature xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
    <dsig:SignedInfo>
      <dsig:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <dsig:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <dsig:Reference URI="">
        <dsig:Transforms>
          <dsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <dsig:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
            <dsig:XPath xmlns:samlp_xpath="urn:oasis:names:tc:SAML:1.0:protocol" >
              count(ancestor-or-self::samlp_xpath:Response |
              here()/ancestor::samlp_xpath:Response[1]) =
              count(ancestor-or-self::samlp_xpath:Response)
            </dsig:XPath>
          </dsig:Transform>
        </dsig:Transforms>
        <dsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <dsig:DigestValue/>
      </dsig:Reference>
    </dsig:SignedInfo>
    <dsig:SignatureValue/>
    <dsig:KeyInfo>
      <dsig:KeyName>MyKey</dsig:KeyName>
      <dsig:X509Data/>
    </dsig:KeyInfo>
  </dsig:Signature>
  <Status>
    <StatusCode Value="samlp:Success"/>
  </Status>
  <Assertion xmlns="urn:oasis:names:tc:SAML:1.0:assertion" AssertionID="7ddc31-ed4a03d735-FB24AD27D96135B68C99FB9AACFE2FFC" IssueInstant="2002-04-18T16:56:54Z" Issuer="hs.osu.edu" MajorVersion="1" MinorVersion="0">
    <Conditions NotBefore="2002-04-18T16:56:54Z" NotOnOrAfter="2002-04-18T17:01:54Z">
      <AudienceRestrictionCondition>
        <Audience>http://middleware.internet2.edu/shibboleth/clubs/clubshib/1.0/</Audience>
      </AudienceRestrictionCondition>
    </Conditions>
    <AuthenticationStatement AuthenticationInstant="2002-04-18T16:56:53Z" AuthenticationMethod="urn:mace:shibboleth:authmethod">
      <Subject>
        <NameIdentifier Format="urn:mace:shibboleth:1.0:handle" NameQualifier="osu.edu">foo</NameIdentifier>
        <SubjectConfirmation>
          <ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:Bearer</ConfirmationMethod>
        </SubjectConfirmation>
      </Subject>
      <SubjectLocality IPAddress="127.0.0.1"/>
      <AuthorityBinding AuthorityKind="samlp:AttributeQuery" Binding="urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding" Location="https://aa.osu.edu/"/>
    </AuthenticationStatement>
  </Assertion>
</Response>
```

## Invalid Result: `verify-saml-bad-res.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!--
XML Security Library example: A simple bad SAML response template (verify-saml example).

Sign it using the following command (replace __ with double dashes):

 $ xmlsec1 sign __privkey:MyKey rsakey.pem,rsacert.pem __output verify-saml-bad-res.xml verify-saml-bad-tmpl.xml
-->
<Response xmlns="urn:oasis:names:tc:SAML:1.0:protocol" xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" IssueInstant="2002-04-18T16:56:54Z" MajorVersion="1" MinorVersion="0" Recipient="https://shire.target.com" ResponseID="7ddc31-ed4a03d703-FB24AD27D96135B68C99FB9AACFE2FFC">
  <dsig:Signature xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
    <dsig:SignedInfo>
      <dsig:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <dsig:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <dsig:Reference URI="">
        <dsig:Transforms>
          <dsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <dsig:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
            <dsig:XPath xmlns:samlp_xpath="urn:oasis:names:tc:SAML:1.0:protocol">
              count(ancestor-or-self::samlp_xpath:Response |
              here()/ancestor::samlp_xpath:Response[1]) =
              count(ancestor-or-self::samlp_xpath:Response)
            </dsig:XPath>
          </dsig:Transform>
        </dsig:Transforms>
        <dsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <dsig:DigestValue>t1nvDq1bZXEhBIXc/DHcqIrjRyI=</dsig:DigestValue>
      </dsig:Reference>
    </dsig:SignedInfo>
    <dsig:SignatureValue>qYsjCJcQqJRYkbUJ1DgbzFiqfYaXr/YxwLp8kWWg54lWU+bDqxjzTrFLa2QE52hq
1Oc3xO93fNWhErpfrzFfQA==</dsig:SignatureValue>
    <dsig:KeyInfo>
      <dsig:KeyName>MyKey</dsig:KeyName>
      <dsig:X509Data>
<dsig:X509Certificate>MIIDpzCCA1GgAwIBAgIJAK+ii7kzrdqvMA0GCSqGSIb3DQEBBQUAMIGcMQswCQYD
VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTE9MDsGA1UEChM0WE1MIFNlY3Vy
aXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20veG1sc2VjKTEWMBQG
A1UEAxMNQWxla3NleSBTYW5pbjEhMB8GCSqGSIb3DQEJARYSeG1sc2VjQGFsZWtz
ZXkuY29tMCAXDTE0MDUyMzE3NTUzNFoYDzIxMTQwNDI5MTc1NTM0WjCBxzELMAkG
A1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExPTA7BgNVBAoTNFhNTCBTZWN1
cml0eSBMaWJyYXJ5IChodHRwOi8vd3d3LmFsZWtzZXkuY29tL3htbHNlYykxKTAn
BgNVBAsTIFRlc3QgVGhpcmQgTGV2ZWwgUlNBIENlcnRpZmljYXRlMRYwFAYDVQQD
Ew1BbGVrc2V5IFNhbmluMSEwHwYJKoZIhvcNAQkBFhJ4bWxzZWNAYWxla3NleS5j
b20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEA09BtD3aeVt6DVDkk0dI7Vh7Ljqdn
sYmW0tbDVxxK+nume+Z9Sb4znbUKkWl+vgQATdRUEyhT2P+Gqrd0UBzYfQIDAQAB
o4IBRTCCAUEwDAYDVR0TBAUwAwEB/zAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBH
ZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFNf0xkZ3zjcEI60pVPuwDqTM
QygZMIHjBgNVHSMEgdswgdiAFP7k7FMk8JWVxxC14US1XTllWuN+oYG0pIGxMIGu
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTE9MDsGA1UEChM0WE1M
IFNlY3VyaXR5IExpYnJhcnkgKGh0dHA6Ly93d3cuYWxla3NleS5jb20veG1sc2Vj
KTEQMA4GA1UECxMHUm9vdCBDQTEWMBQGA1UEAxMNQWxla3NleSBTYW5pbjEhMB8G
CSqGSIb3DQEJARYSeG1sc2VjQGFsZWtzZXkuY29tggkAr6KLuTOt2q0wDQYJKoZI
hvcNAQEFBQADQQAOXBj0yICp1RmHXqnUlsppryLCW3pKBD1dkb4HWarO7RjA1yJJ
fBjXssrERn05kpBcrRfzou4r3DCgQFPhjxga
</dsig:X509Certificate>
</dsig:X509Data>
    </dsig:KeyInfo>
  </dsig:Signature>
  <Status>
    <StatusCode Value="samlp:Success"/>
  </Status>
  <Assertion xmlns="urn:oasis:names:tc:SAML:1.0:assertion" AssertionID="7ddc31-ed4a03d735-FB24AD27D96135B68C99FB9AACFE2FFC" IssueInstant="2002-04-18T16:56:54Z" Issuer="hs.osu.edu" MajorVersion="1" MinorVersion="0">
    <Conditions NotBefore="2002-04-18T16:56:54Z" NotOnOrAfter="2002-04-18T17:01:54Z">
      <AudienceRestrictionCondition>
        <Audience>http://middleware.internet2.edu/shibboleth/clubs/clubshib/1.0/</Audience>
      </AudienceRestrictionCondition>
    </Conditions>
    <AuthenticationStatement AuthenticationInstant="2002-04-18T16:56:53Z" AuthenticationMethod="urn:mace:shibboleth:authmethod">
      <Subject>
        <NameIdentifier Format="urn:mace:shibboleth:1.0:handle" NameQualifier="osu.edu">foo</NameIdentifier>
        <SubjectConfirmation>
          <ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:Bearer</ConfirmationMethod>
        </SubjectConfirmation>
      </Subject>
      <SubjectLocality IPAddress="127.0.0.1"/>
      <AuthorityBinding AuthorityKind="samlp:AttributeQuery" Binding="urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding" Location="https://aa.osu.edu/"/>
    </AuthenticationStatement>
  </Assertion>
</Response>
```

