/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @addtogroup xmlsec_core_helpers
 * @brief Utility functions.
 * Various utility functions.
 */
#include "globals.h"

#include <string.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/dl.h>
#include <xmlsec/io.h>
#include <xmlsec/errors.h>

#include "cast_helpers.h"


/* default external entity loader, pointer saved during xmlSecInit */
static xmlExternalEntityLoader xmlSecDefaultExternalEntityLoader = NULL;

/* new parser option XML_PARSE_NO_XXE available since 2.13.0 */
#if LIBXML_VERSION < 21300
/*
 * Custom external entity handler, denies all files except the initial
 * document we're parsing. libxml2 (< 2.13) routes every external load
 * through the process-wide loader set by xmlSetExternalEntityLoader():
 * external general entities, external DTD subsets, and the initial
 * document when loaded via xmlCreateURLParserCtxt() or xmlCtxtReadFile()
 * (xmlCreateFileParserCtxt() and xmlCreateMemoryParserCtxt() create the
 * document input directly and do not involve the loader). The initial
 * document load invokes the loader on a context with no input on the
 * stack (ctxt->input == NULL) before the document input stream is
 * created; a fresh context starts with ctxt->input_id == 1 and every
 * new input stream increments it (xmlNewInputStream()), so a
 * fresh-context document load is the only case with input_id <= 1 at
 * the loader call. External general entities are loaded in a freshly
 * created context (xmlCreateEntityParserCtxtInternal()) that gets
 * input_id from the context the entity is referenced in, which has
 * input_id > 1 by then, so entity loads are always denied. External DTD
 * subsets are loaded while the document input is already on the stack
 * (ctxt->input != NULL) and are denied as well.
 * Note: the initial document of a reused context (e.g. a second
 * xmlCtxtReadFile() on the same context) is also denied:
 * xmlCtxtReset() does not reset input_id, so at that point the context
 * state (no input on the stack, input_id > 1) is indistinguishable from
 * the fresh entity context above. xmlsec's own parse functions always
 * use fresh parser contexts, so this only affects applications that
 * reuse contexts for direct libxml2 loads.
 */
static xmlParserInputPtr
xmlSecNoXxeExternalEntityLoader(
    const char *URL, const char *ID, xmlParserCtxtPtr ctxt) {
    if(ctxt == NULL) {
        return(NULL);
    }
    if((ctxt->input == NULL) && (ctxt->input_id <= 1)) {
        if(xmlSecDefaultExternalEntityLoader == NULL) {
            xmlSecXmlError("xmlSecNoXxeExternalEntityLoader", NULL);
            return(NULL);
        }
        return xmlSecDefaultExternalEntityLoader(URL, ID, ctxt);
    }
    xmlSecXmlError2("xmlSecNoXxeExternalEntityLoader", NULL,
                    "illegal external entity='%s'", xmlSecErrorsSafeString(URL));
    return(NULL);
}

#endif /* LIBXML_VERSION < 21300 */

/**
 * @brief Wrapper for xmlSetExternalEntityLoader.
 * @param entityLoader the new entity resolver function, or NULL to restore the loader
 * that was in effect when the library was initialized
 */
void
xmlSecSetExternalEntityLoader(xmlExternalEntityLoader entityLoader) {
    if(entityLoader != NULL) {
        xmlSetExternalEntityLoader(entityLoader);
    } else if(xmlSecDefaultExternalEntityLoader != NULL) {
        xmlSetExternalEntityLoader(xmlSecDefaultExternalEntityLoader);
    } else {
        /* log an error but ignore it (non critical) */
        xmlSecXmlError("xmlSecSetExternalEntityLoader", NULL);
    }
}


/**
 * @brief Initializes XML Security Library.
 * @details Initializes XML Security Library. The dependent libraries
 * (LibXML and LibXSLT) must be initialized before calling this function.
 *
 * Note: The application SHOULD NOT initialize the XML Security Library
 * more than once per process. Re-initialization is not supported: a second
 * call re-runs the sub-initialization routines, which re-initialize the
 * global lists (IO callbacks, key data, transforms) and orphan the
 * first-generation data (the dynamically allocated xmlSecIOCallbacks
 * structs are never freed), resulting in a bounded one-time memory leak.
 *
 * Note: in case of failure the library is left partially
 * initialized and this state is not recoverable.
 *
 * @return 0 on success or a negative value otherwise.
 */
int
xmlSecInit(void) {
    xmlSecErrorsInit();

    if(xmlSecIOInit() < 0) {
        xmlSecInternalError("xmlSecIOInit", NULL);
        return(-1);
    }

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

    /* initialize safe external entity loader */
    if(!xmlSecDefaultExternalEntityLoader) {
        xmlSecDefaultExternalEntityLoader = xmlGetExternalEntityLoader();
    }

    /* libxml2 >= 2.13.0 provides the XML_PARSE_NO_XXE parser option, which is
     * included in xmlsec's default parser options mask (see src/parser.c);
     * for older libxml2 versions the external entity loader below is used
     * instead */
#if LIBXML_VERSION < 21300
    xmlSetExternalEntityLoader(xmlSecNoXxeExternalEntityLoader);
#endif /* LIBXML_VERSION < 21300 */

    /* success */
    return(0);
}

/**
 * @brief Cleans up the XML Security Library.
 * @details Cleans up the XML Security Library.
 *
 * Note: Once this function has been called it might be
 * impossible to reinitialize the library correctly.
 *
 * @return 0 on success or a negative value otherwise.
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

#if LIBXML_VERSION < 21300
    /* restore the original external entity loader */
    if(xmlSecDefaultExternalEntityLoader != NULL) {
        xmlSetExternalEntityLoader(xmlSecDefaultExternalEntityLoader);
        xmlSecDefaultExternalEntityLoader = NULL;
    }
#endif /* LIBXML_VERSION < 21300 */

    xmlSecIOShutdown();
    xmlSecErrorsShutdown();
    return(res);
}

/**
 * @brief Gets the default crypto engine for the XML Security Library.
 * @details Gets the default crypto engine ("openssl", "nss", etc.) for the XML Security Library.
 *
 * @return the default crypto engine ("openssl", "nss", etc.).
 */
const xmlChar*
xmlSecGetDefaultCrypto(void) {
    return BAD_CAST XMLSEC_DEFAULT_CRYPTO;
}

/**
 * @brief Checks if the loaded version of xmlsec library could be used.
 * @param major the major version number.
 * @param minor the minor version number.
 * @param subminor the subminor version number.
 * @param mode the version check mode.
 *
 * @return 1 if the loaded xmlsec library version is OK to use,
 * 0 if it is not.
 */
int
xmlSecCheckVersionExt(int major, int minor, int subminor, xmlSecCheckVersionMode mode) {
    /* we always want to have a match for major version number */
    if(major != XMLSEC_VERSION_MAJOR) {
        xmlSecOtherError3(XMLSEC_ERRORS_R_INVALID_VERSION, NULL,
                "library major version=%d;required major version=%d",
                XMLSEC_VERSION_MAJOR, major);
        return(0);
    }

    switch(mode) {
    case xmlSecCheckVersionExactMatch:
        if((minor != XMLSEC_VERSION_MINOR) || (subminor != XMLSEC_VERSION_SUBMINOR)) {
            xmlSecOtherError5(XMLSEC_ERRORS_R_INVALID_VERSION, NULL,
                    "mode=exact;library minor version=%d;required minor version=%d;library subminor version=%d;required subminor version=%d",
                    XMLSEC_VERSION_MINOR, minor, XMLSEC_VERSION_SUBMINOR, subminor);
            return(0);
        }
        break;
    case xmlSecCheckVersionABICompatible:
        if((minor > XMLSEC_VERSION_MINOR) || ((minor == XMLSEC_VERSION_MINOR) &&
                (subminor > XMLSEC_VERSION_SUBMINOR))) {
            xmlSecOtherError5(XMLSEC_ERRORS_R_INVALID_VERSION, NULL,
                    "mode=abi compatible;library minor version=%d;required minor version=%d;library subminor version=%d;required subminor version=%d",
                    XMLSEC_VERSION_MINOR, minor, XMLSEC_VERSION_SUBMINOR, subminor);
            return(0);
        }
        break;
    default:
        xmlSecUnsupportedEnumValueError("mode", mode, NULL);
        return(0);
    }

    return(1);
}

/**
 * @brief Calculates the length of the string.
 * @param str the string.
 *
 * @return the length of the string.
 */
xmlSecSize
xmlSecStrlen(const xmlChar* str) {
    if(str == NULL) {
        return(0);
    }
    return(strlen((const char*)str));
}
