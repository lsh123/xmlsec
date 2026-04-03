# Initialization and shutdown

XML Security Library initialization/shutdown process includes initialization and shutdown of the dependent libraries:
- libxml library;
- libxslt library;
- crypto library (OpenSSL, GnuTLS, GCrypt, NSS, ...);
- xmlsec library ( [xmlSecInit](#xmlsecinit) and [xmlSecShutdown](#xmlsecshutdown) functions);
- xmlsec-crypto library ( [xmlSecCryptoDLLoadLibrary](#xmlseccryptodlloadlibrary) to load xmlsec-crypto library dynamicaly if needed, [xmlSecCryptoInit](#xmlseccryptoinit) and [xmlSecCryptoShutdown](#xmlseccryptoshutdown) functions);
xmlsec-crypto library also provides a convinient functions [xmlSecAppCryptoInit](#xmlsecappcryptoinit) and [xmlSecAppCryptoShutdown](#xmlsecappcryptoshutdown) to initialize the crypto library itself but application can do it by itself.

**Example: Initializing application**
```
    /* Init libxml and libxslt libraries */
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);
#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1;
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
			"(LD_LIBRARY_PATH) envornment variable.\n");
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

**Example: Shutting down application**
```
    /* Shutdown xmlsec-crypto library */
    xmlSecCryptoShutdown();

    /* Shutdown crypto library */
    xmlSecCryptoAppShutdown();

    /* Shutdown xmlsec library */
    xmlSecShutdown();

    /* Shutdown libxslt/libxml */
#ifndef XMLSEC_NO_XSLT
    xsltCleanupGlobals();
#endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();
```

