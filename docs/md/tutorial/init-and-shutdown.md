# Initialization and shutdown

The XML Security Library initialization and shutdown process includes
initializing and shutting down the following dependencies:
- the libxml2 library;
- the libxslt library;
- a crypto library such as OpenSSL, NSS, or GnuTLS (the
    `xmlsec-crypto` library provides the convenience functions
    [xmlSecCryptoAppInit](../api/xmlsec_core_app.md#xmlseccryptoappinit)
    and
    [xmlSecCryptoAppShutdown](../api/xmlsec_core_app.md#xmlseccryptoappshutdown));
- the xmlsec library
    ([xmlSecInit](../api/xmlsec_core_helpers.md#xmlsecinit) and
    [xmlSecShutdown](../api/xmlsec_core_helpers.md#xmlsecshutdown));
- the xmlsec-crypto library
    ([xmlSecCryptoDLLoadLibrary](../api/xmlsec_core_dl.md#xmlseccryptodlloadlibrary)
    for dynamic loading when needed,
    [xmlSecCryptoInit](../api/xmlsec_core_app.md#xmlseccryptoinit), and
    [xmlSecCryptoShutdown](../api/xmlsec_core_app.md#xmlseccryptoshutdown)).

## Example: Initializing an application

```c
    /* Init LibXML2 */
    xmlInitParser();
    LIBXML_TEST_VERSION

    /* Init LibXSLT */
#ifndef XMLSEC_NO_XSLT
    /* disable all XSLT file and network access */
    xsltSecPrefs = xsltNewSecurityPrefs();
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_FILE,        xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_FILE,       xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_NETWORK,     xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_NETWORK,    xsltSecurityForbid);
    xsltSetDefaultSecurityPrefs(xsltSecPrefs);
#endif /* XMLSEC_NO_XSLT */

    /* Init XMLSec */
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
```

## Example: Shutting down an application

```c
    /* Shutdown xmlsec-crypto library */
    xmlSecCryptoShutdown();

    /* Shutdown crypto library */
    xmlSecCryptoAppShutdown();

    /* Shutdown XMLSec */
    xmlSecShutdown();

    /* Shutdown LibXSLT / LibXML2*/
#ifndef XMLSEC_NO_XSLT
    xsltFreeSecurityPrefs(xsltSecPrefs);
    xsltCleanupGlobals();
#endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();
```

[Full program listing](../examples/sign1.md)