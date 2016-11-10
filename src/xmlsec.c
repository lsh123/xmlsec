/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * General functions.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2016 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/app.h>
#include <xmlsec/io.h>
#include <xmlsec/errors.h>

/**
 * xmlSecInit:
 *
 * Initializes XML Security Library. The depended libraries
 * (LibXML and LibXSLT) must be initialized before.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecInit(void) {
    xmlSecErrorsInit();
    xmlSecIOInit();

#ifndef XMLSEC_NO_CRYPTO_DYNAMIC_LOADING
    if(xmlSecCryptoDLInit() < 0) {
        xmlSecInternalError("xmlSecCryptoDLInit", NULL);

        return(-1);
    }
#endif /* XMLSEC_NO_CRYPTO_DYNAMIC_LOADING */

    if(xmlSecKeyDataIdsInit() < 0) {
        xmlSecInternalError("xmlSecKeyDataIdsInit", NULL);

        return(-1);
    }

    if(xmlSecTransformIdsInit() < 0) {
        xmlSecInternalError("xmlSecTransformIdsInit", NULL);

        return(-1);
    }



    /* we use rand() function to generate id attributes */
    srand(time(NULL));
    return(0);
}

/**
 * xmlSecShutdown:
 *
 * Clean ups the XML Security Library.
 *
 * Returns: 0 on success or a negative value otherwise.
 */
int
xmlSecShutdown(void) {
    int res = 0;

    xmlSecTransformIdsShutdown();
    xmlSecKeyDataIdsShutdown();

#ifndef XMLSEC_NO_CRYPTO_DYNAMIC_LOADING
    if(xmlSecCryptoDLShutdown() < 0) {
        xmlSecInternalError("xmlSecCryptoDLShutdown", NULL);

        res = -1;
    }
#endif /* XMLSEC_NO_CRYPTO_DYNAMIC_LOADING */

    xmlSecIOShutdown();
    xmlSecErrorsShutdown();
    return(res);
}

/**
 * xmlSecShutdown:
 *
 * Gets the default crypto engine ("openssl", "nss", etc.) for the XML Security Library.
 *
 * Returns: the default crypto engine ("openssl", "nss", etc.).
 */
const xmlChar * xmlSecGetDefaultCrypto(void) {
    return BAD_CAST XMLSEC_DEFAULT_CRYPTO;
}

/**
 * xmlSecCheckVersionExt:
 * @major:              the major version number.
 * @minor:              the minor version number.
 * @subminor:           the subminor version number.
 * @mode:               the version check mode.
 *
 * Checks if the loaded version of xmlsec library could be used.
 *
 * Returns: 1 if the loaded xmlsec library version is OK to use
 * 0 if it is not or a negative value if an error occurs.
 */
int
xmlSecCheckVersionExt(int major, int minor, int subminor, xmlSecCheckVersionMode mode) {
    /* we always want to have a match for major version number */
    if(major != XMLSEC_VERSION_MAJOR) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_VERSION,
                    "expected major version=%d;real major version=%d",
                    XMLSEC_VERSION_MAJOR, major);
        return(0);
    }

    switch(mode) {
    case xmlSecCheckVersionExactMatch:
        if((minor != XMLSEC_VERSION_MINOR) || (subminor != XMLSEC_VERSION_SUBMINOR)) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        NULL,
                        XMLSEC_ERRORS_R_INVALID_VERSION,
                        "mode=exact;expected minor version=%d;real minor version=%d;expected subminor version=%d;real subminor version=%d",
                        XMLSEC_VERSION_MINOR, minor,
                        XMLSEC_VERSION_SUBMINOR, subminor);
            return(0);
        }
        break;
    case xmlSecCheckVersionABICompatible:
        if((minor > XMLSEC_VERSION_MINOR) ||
           ((minor == XMLSEC_VERSION_MINOR) &&
            (subminor > XMLSEC_VERSION_SUBMINOR))) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        NULL,
                        XMLSEC_ERRORS_R_INVALID_VERSION,
                        "mode=abi compatible;expected minor version=%d;real minor version=%d;expected subminor version=%d;real subminor version=%d",
                        XMLSEC_VERSION_MINOR, minor,
                        XMLSEC_VERSION_SUBMINOR, subminor);
            return(0);
        }
        break;
    }

    return(1);
}


