/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:dl
 * @Short_description: Dynamic crypto-engine library loading functions.
 * @Stability: Stable
 *
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/app.h>
#include <xmlsec/list.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/private.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/errors.h>
#include <xmlsec/dl.h>

#ifndef XMLSEC_NO_CRYPTO_DYNAMIC_LOADING

#ifdef XMLSEC_DL_LIBLTDL
#include <ltdl.h>
#endif /* XMLSEC_DL_LIBLTDL */

#if defined(XMLSEC_WINDOWS) && defined(XMLSEC_DL_WIN32)
#include <windows.h>
#endif /* defined(XMLSEC_WINDOWS) && defined(XMLSEC_DL_WIN32) */

#include "cast_helpers.h"

/***********************************************************************
 *
 * loaded libraries list
 *
 **********************************************************************/
typedef struct _xmlSecCryptoDLLibrary                                   xmlSecCryptoDLLibrary,
                                                                        *xmlSecCryptoDLLibraryPtr;
struct _xmlSecCryptoDLLibrary {
    xmlChar*    name;
    xmlChar*    filename;
    xmlChar*    getFunctionsName;
    xmlSecCryptoDLFunctionsPtr functions;

#ifdef XMLSEC_DL_LIBLTDL
    lt_dlhandle handle;
#endif /* XMLSEC_DL_LIBLTDL */

#if defined(XMLSEC_WINDOWS) && defined(XMLSEC_DL_WIN32)
    HINSTANCE   handle;
#endif /* defined(XMLSEC_WINDOWS) && defined(XMLSEC_DL_WIN32) */
};

static xmlSecCryptoDLLibraryPtr xmlSecCryptoDLLibraryCreate             (const xmlChar* name);
static void                     xmlSecCryptoDLLibraryDestroy            (xmlSecCryptoDLLibraryPtr lib);
static xmlSecCryptoDLLibraryPtr xmlSecCryptoDLLibraryDuplicate          (xmlSecCryptoDLLibraryPtr lib);
static xmlChar*                 xmlSecCryptoDLLibraryConstructFilename  (const xmlChar* name);
static xmlChar*                 xmlSecCryptoDLLibraryConstructGetFunctionsName(const xmlChar* name);


static xmlSecPtrListKlass xmlSecCryptoDLLibrariesListKlass = {
    BAD_CAST "dl-libraries-list",
    (xmlSecPtrDuplicateItemMethod)xmlSecCryptoDLLibraryDuplicate,/* xmlSecPtrDuplicateItemMethod duplicateItem; */
    (xmlSecPtrDestroyItemMethod)xmlSecCryptoDLLibraryDestroy,   /* xmlSecPtrDestroyItemMethod destroyItem; */
    NULL,                                                       /* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    NULL,                                                       /* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};
static xmlSecPtrListId          xmlSecCryptoDLLibrariesListGetKlass     (void);
static int                      xmlSecCryptoDLLibrariesListFindByName   (xmlSecPtrListPtr list,
                                                                         const xmlChar* name,
                                                                         xmlSecSize* pos);

typedef xmlSecCryptoDLFunctionsPtr xmlSecCryptoGetFunctionsCallback(void);

/* conversion from ptr to func "the right way" */
XMLSEC_PTR_TO_FUNC_IMPL(xmlSecCryptoGetFunctionsCallback)


static xmlSecCryptoDLLibraryPtr
xmlSecCryptoDLLibraryCreate(const xmlChar* name) {
    xmlSecCryptoDLLibraryPtr lib;
    xmlSecCryptoGetFunctionsCallback * getFunctions = NULL;

    xmlSecAssert2(name != NULL, NULL);

    /* fprintf (stderr, "loading \"library %s\"...\n", name); */

    /* Allocate a new xmlSecCryptoDLLibrary and fill the fields. */
    lib = (xmlSecCryptoDLLibraryPtr)xmlMalloc(sizeof(xmlSecCryptoDLLibrary));
    if(lib == NULL) {
        xmlSecMallocError(sizeof(xmlSecCryptoDLLibrary), NULL);
        return(NULL);
    }
    memset(lib, 0, sizeof(xmlSecCryptoDLLibrary));

    lib->name = xmlStrdup(name);
    if(lib->name == NULL) {
        xmlSecStrdupError(name, NULL);
        xmlSecCryptoDLLibraryDestroy(lib);
        return(NULL);
    }

    lib->filename = xmlSecCryptoDLLibraryConstructFilename(name);
    if(lib->filename == NULL) {
        xmlSecInternalError("xmlSecCryptoDLLibraryConstructFilename", NULL);
        xmlSecCryptoDLLibraryDestroy(lib);
        return(NULL);
    }

    lib->getFunctionsName = xmlSecCryptoDLLibraryConstructGetFunctionsName(name);
    if(lib->getFunctionsName == NULL) {
        xmlSecInternalError("xmlSecCryptoDLLibraryConstructGetFunctionsName", NULL);
        xmlSecCryptoDLLibraryDestroy(lib);
        return(NULL);
    }

#ifdef XMLSEC_DL_LIBLTDL
    lib->handle = lt_dlopenext((char*)lib->filename);
    if(lib->handle == NULL) {
        xmlSecIOError("lt_dlopenext", lib->filename, NULL);
        xmlSecCryptoDLLibraryDestroy(lib);
        return(NULL);
    }

    getFunctions = XMLSEC_PTR_TO_FUNC(xmlSecCryptoGetFunctionsCallback,
                        lt_dlsym(lib->handle, (char*)lib->getFunctionsName)
                    );
    if(getFunctions == NULL) {
        xmlSecIOError("lt_dlsym", lib->getFunctionsName, NULL);
        xmlSecCryptoDLLibraryDestroy(lib);
        return(NULL);
    }
#endif /* XMLSEC_DL_LIBLTDL */

#if defined(XMLSEC_WINDOWS) && defined(XMLSEC_DL_WIN32)
#if !defined(WINAPI_FAMILY) || (WINAPI_FAMILY == WINAPI_FAMILY_DESKTOP_APP)
    lib->handle = LoadLibraryA((char*)lib->filename);
#else
    LPWSTR wcLibFilename = xmlSecWin32ConvertUtf8ToUnicode(lib->filename);
    if(wcLibFilename == NULL) {
        xmlSecIOError("xmlSecWin32ConvertUtf8ToTstr", lib->filename, NULL);
        xmlSecCryptoDLLibraryDestroy(lib);
        return(NULL);
    }
    lib->handle = LoadPackagedLibrary(wcLibFilename, 0);
    xmlFree(wcLibFilename);
#endif
    if(lib->handle == NULL) {
        xmlSecIOError("LoadLibraryA", lib->filename, NULL);
        xmlSecCryptoDLLibraryDestroy(lib);
        return(NULL);
    }

    getFunctions = XMLSEC_PTR_TO_FUNC(xmlSecCryptoGetFunctionsCallback,
                        GetProcAddress(
                            lib->handle,
                            (const char*)lib->getFunctionsName
                        )
                    );
    if(getFunctions == NULL) {
        xmlSecIOError("GetProcAddressA", lib->getFunctionsName, NULL);
        xmlSecCryptoDLLibraryDestroy(lib);
        return(NULL);
    }
#endif /* defined(XMLSEC_WINDOWS) && defined(XMLSEC_DL_WIN32) */

    if(getFunctions == NULL) {
        xmlSecInternalError("invalid configuration: no way to load library", NULL);
        xmlSecCryptoDLLibraryDestroy(lib);
        return(NULL);
    }

    lib->functions = getFunctions();
    if(lib->functions == NULL) {
        xmlSecInternalError("getFunctions", NULL);
        xmlSecCryptoDLLibraryDestroy(lib);
        return(NULL);
    }

    /* fprintf (stderr, "library %s loaded\n", name); */
    return(lib);
}

static void
xmlSecCryptoDLLibraryDestroy(xmlSecCryptoDLLibraryPtr lib) {
    xmlSecAssert(lib != NULL);

    /* fprintf (stderr, "unloading \"library %s\"...\n", lib->name); */
    if(lib->name != NULL) {
        xmlFree(lib->name);
    }

    if(lib->filename != NULL) {
        xmlFree(lib->filename);
    }

    if(lib->getFunctionsName != NULL) {
        xmlFree(lib->getFunctionsName);
    }

#ifdef XMLSEC_DL_LIBLTDL
    if(lib->handle != NULL) {
        int ret;

        ret = lt_dlclose(lib->handle);
        if(ret != 0) {
            xmlSecIOError("lt_dlclose", NULL, NULL);
            /* ignore error */
        }
    }
#endif /* XMLSEC_DL_LIBLTDL */

#if defined(XMLSEC_WINDOWS) && defined(XMLSEC_DL_WIN32)
    if(lib->handle != NULL) {
        BOOL res;

        res = FreeLibrary(lib->handle);
        if(!res) {
            xmlSecIOError("FreeLibrary", NULL, NULL);
            /* ignore error */
        }
        }
#endif /* defined(XMLSEC_WINDOWS) && defined(XMLSEC_DL_WIN32)*/

    memset(lib, 0, sizeof(xmlSecCryptoDLLibrary));
    xmlFree(lib);
}

static xmlSecCryptoDLLibraryPtr
xmlSecCryptoDLLibraryDuplicate(xmlSecCryptoDLLibraryPtr lib) {
    xmlSecAssert2(lib != NULL, NULL);
    xmlSecAssert2(lib->name != NULL, NULL);

    return(xmlSecCryptoDLLibraryCreate(lib->name));
}

#define XMLSEC_CRYPTO_DL_LIB_TMPL   "lib%s-%s"
static xmlChar*
xmlSecCryptoDLLibraryConstructFilename(const xmlChar* name) {
    xmlChar* res;
    xmlSecSize size;
    int len;
    int ret;

    xmlSecAssert2(name != NULL, NULL);

    size = xmlSecStrlen(BAD_CAST PACKAGE) +
           xmlSecStrlen(name) +
           xmlSecStrlen(BAD_CAST XMLSEC_CRYPTO_DL_LIB_TMPL) +
           1;
    XMLSEC_SAFE_CAST_SIZE_TO_INT(size, len, return(NULL), NULL);

    res = (xmlChar*)xmlMalloc(size + 1);
    if(res == NULL) {
        xmlSecMallocError(size + 1, NULL);
        return(NULL);
    }

    ret = xmlStrPrintf(res, len, XMLSEC_CRYPTO_DL_LIB_TMPL, PACKAGE, name);
    if(ret < 0) {
        xmlSecXmlError("xmlStrPrintf", NULL);
        xmlFree(res);
        return(NULL);
    }

    return(res);
}

#define XMLSEC_CRYPTO_DL_GET_FUNCTIONS_TMPL  "xmlSecCryptoGetFunctions_%s"

static xmlChar*
xmlSecCryptoDLLibraryConstructGetFunctionsName(const xmlChar* name) {
    xmlChar* res;
    int len;
    xmlSecSize size;
    int ret;

    xmlSecAssert2(name != NULL, NULL);

    len = xmlStrlen(name) + xmlStrlen(BAD_CAST XMLSEC_CRYPTO_DL_GET_FUNCTIONS_TMPL) + 1;
    XMLSEC_SAFE_CAST_INT_TO_SIZE(len, size, return(NULL), -1);

    res = (xmlChar*)xmlMalloc(size + 1);
    if(res == NULL) {
        xmlSecMallocError(size + 1, NULL);
        return(NULL);
    }

    ret = xmlStrPrintf(res, len, XMLSEC_CRYPTO_DL_GET_FUNCTIONS_TMPL, name);
    if(ret < 0) {
        xmlSecXmlError("xmlStrPrintf", NULL);
        xmlFree(res);
        return(NULL);
    }

    return(res);
}

static xmlSecPtrListId
xmlSecCryptoDLLibrariesListGetKlass(void) {
    return(&xmlSecCryptoDLLibrariesListKlass);
}

static int
xmlSecCryptoDLLibrariesListFindByName(xmlSecPtrListPtr list, const xmlChar* name, xmlSecSize* pos) {
    xmlSecSize ii, size;
    xmlSecCryptoDLLibraryPtr lib;

    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecCryptoDLLibrariesListGetKlass()), -1);
    xmlSecAssert2(name != NULL, -1);
    xmlSecAssert2(pos != NULL, -1);

    size = xmlSecPtrListGetSize(list);
    for(ii = 0; ii < size; ++ii) {
        lib = (xmlSecCryptoDLLibraryPtr)xmlSecPtrListGetItem(list, ii);
        if((lib != NULL) && (lib->name != NULL) && (xmlStrcmp(lib->name, name) == 0)) {
            (*pos) = ii;
            return(0);
        }
    }
    return(-1);
}

/******************************************************************************
 *
 * Dynamic load functions
 *
 *****************************************************************************/
static xmlSecCryptoDLFunctionsPtr gXmlSecCryptoDLFunctions = NULL;
static xmlSecPtrList gXmlSecCryptoDLLibraries;

/**
 * xmlSecCryptoDLInit:
 *
 * Initializes dynamic loading engine. This is an internal function
 * and should not be called by application directly.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecCryptoDLInit(void) {
    int ret;

    ret = xmlSecPtrListInitialize(&gXmlSecCryptoDLLibraries,
                                  xmlSecCryptoDLLibrariesListGetKlass());
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListInitialize",
                            "xmlSecCryptoDLLibrariesListGetKlass");
        return(-1);
    }

#ifdef XMLSEC_DL_LIBLTDL
    ret = lt_dlinit ();
    if(ret != 0) {
        xmlSecIOError("lt_dlinit", NULL, NULL);
        return(-1);
    }
#endif /* XMLSEC_DL_LIBLTDL */

    return(0);
}


/**
 * xmlSecCryptoDLShutdown:
 *
 * Shutdowns dynamic loading engine. This is an internal function
 * and should not be called by application directly.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecCryptoDLShutdown(void) {
    int ret;

    xmlSecPtrListFinalize(&gXmlSecCryptoDLLibraries);

#ifdef XMLSEC_DL_LIBLTDL
    ret = lt_dlexit ();
    if(ret != 0) {
        xmlSecIOError("lt_dlexit", NULL, NULL);
        /* ignore error */
    }
#else  /* XMLSEC_DL_LIBLTDL */
    UNREFERENCED_PARAMETER(ret);
#endif /* XMLSEC_DL_LIBLTDL */

    return(0);
}

/**
 * xmlSecCryptoDLLoadLibrary:
 * @crypto:             the desired crypto library name ("openssl", "nss", ...). If NULL
 *                      then the default crypto engine will be used.
 *
 * Loads the xmlsec-$crypto library. This function is NOT thread safe,
 * application MUST NOT call #xmlSecCryptoDLLoadLibrary, #xmlSecCryptoDLGetLibraryFunctions,
 * and #xmlSecCryptoDLUnloadLibrary functions from multiple threads.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecCryptoDLLoadLibrary(const xmlChar* crypto) {
    xmlSecCryptoDLFunctionsPtr functions;
    int ret;

    /* if crypto is not specified, then used default */
    functions = xmlSecCryptoDLGetLibraryFunctions((crypto != NULL ) ? crypto : xmlSecGetDefaultCrypto());
    if(functions == NULL) {
        xmlSecInternalError("xmlSecCryptoDLGetLibraryFunctions", NULL);
        return(-1);
    }

    ret = xmlSecCryptoDLSetFunctions(functions);
    if(ret < 0) {
        xmlSecInternalError("xmlSecCryptoDLSetFunctions", NULL);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecCryptoDLGetLibraryFunctions:
 * @crypto:             the desired crypto library name ("openssl", "nss", ...).
 *
 * Loads the xmlsec-$crypto library and gets global crypto functions/transforms/keys data/keys store
 * table. This function is NOT thread safe, application MUST NOT call #xmlSecCryptoDLLoadLibrary,
 * #xmlSecCryptoDLGetLibraryFunctions, and #xmlSecCryptoDLUnloadLibrary functions from multiple threads.
 *
 * Returns: the table or NULL if an error occurs.
 */
xmlSecCryptoDLFunctionsPtr
xmlSecCryptoDLGetLibraryFunctions(const xmlChar* crypto) {
    xmlSecCryptoDLLibraryPtr lib;
    xmlSecSize pos;
    int ret;

    xmlSecAssert2(crypto != NULL, NULL);

    ret = xmlSecCryptoDLLibrariesListFindByName(&gXmlSecCryptoDLLibraries, crypto, &pos);
    if(ret >= 0) {
        lib = (xmlSecCryptoDLLibraryPtr)xmlSecPtrListGetItem(&gXmlSecCryptoDLLibraries, pos);
        xmlSecAssert2(lib != NULL, NULL);
        xmlSecAssert2(lib->functions != NULL, NULL);
        return(lib->functions);
    }

    lib = xmlSecCryptoDLLibraryCreate(crypto);
    if(lib == NULL) {
        xmlSecInternalError2("xmlSecCryptoDLLibraryCreate", NULL,
            "crypto=%s", xmlSecErrorsSafeString(crypto));
        return(NULL);
    }

    ret = xmlSecPtrListAdd(&gXmlSecCryptoDLLibraries, lib);
    if(ret < 0) {
        xmlSecInternalError2("xmlSecPtrListAdd", NULL,
            "crypto=%s", xmlSecErrorsSafeString(crypto));
        xmlSecCryptoDLLibraryDestroy(lib);
        return(NULL);
    }

    return(lib->functions);
}

/**
 * xmlSecCryptoDLUnloadLibrary:
 * @crypto:             the desired crypto library name ("openssl", "nss", ...).
 *
 * Unloads the xmlsec-$crypto library. All pointers to this library
 * functions tables became invalid. This function is NOT thread safe,
 * application MUST NOT call #xmlSecCryptoDLLoadLibrary, #xmlSecCryptoDLGetLibraryFunctions,
 * and #xmlSecCryptoDLUnloadLibrary functions from multiple threads.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecCryptoDLUnloadLibrary(const xmlChar* crypto) {
    xmlSecCryptoDLLibraryPtr lib;
    xmlSecSize pos;
    int ret;

    xmlSecAssert2(crypto != NULL, -1);

    ret = xmlSecCryptoDLLibrariesListFindByName(&gXmlSecCryptoDLLibraries, crypto, &pos);
    if(ret < 0) {
        /* todo: is it an error? */
        return(0);
    }

    lib = (xmlSecCryptoDLLibraryPtr)xmlSecPtrListGetItem(&gXmlSecCryptoDLLibraries, pos);
    if((lib != NULL) && (lib->functions == gXmlSecCryptoDLFunctions)) {
        gXmlSecCryptoDLFunctions = NULL;
    }

    ret = xmlSecPtrListRemove(&gXmlSecCryptoDLLibraries, pos);
    if(ret < 0) {
        xmlSecInternalError("xmlSecPtrListRemove", NULL);
        return(-1);
    }

    return(0);
}

/**
 * xmlSecCryptoDLSetFunctions:
 * @functions:          the new table
 *
 * Sets global crypto functions/transforms/keys data/keys store table.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecCryptoDLSetFunctions(xmlSecCryptoDLFunctionsPtr functions) {
    xmlSecAssert2(functions != NULL, -1);

    gXmlSecCryptoDLFunctions = functions;

    return(0);
}

/**
 * xmlSecCryptoDLGetFunctions:
 *
 * Gets global crypto functions/transforms/keys data/keys store table.
 *
 * Returns: the table.
 */
xmlSecCryptoDLFunctionsPtr
xmlSecCryptoDLGetFunctions(void) {
    return(gXmlSecCryptoDLFunctions);
}

#endif /* XMLSEC_NO_CRYPTO_DYNAMIC_LOADING */


#define XMLSEC_REGISTER_KEY_DATA(name)      \
    if((functions->keyData ## name ## GetKlass != NULL) && (xmlSecKeyDataIdsRegister(functions->keyData ## name ## GetKlass()) < 0)) {    \
        xmlSecInternalError("xmlSecKeyDataIdsRegister", xmlSecKeyDataKlassGetName(functions->keyData ## name ## GetKlass()));             \
        return(-1);                                                                                                                       \
    }                                                                                                                                     \

#define XMLSEC_REGISTER_DISABLED_KEY_DATA(name)      \
    if((functions->keyData ## name ## GetKlass != NULL) && (xmlSecKeyDataIdsRegisterDisabled(functions->keyData ## name ## GetKlass()) < 0)) {    \
        xmlSecInternalError("xmlSecKeyDataIdsRegisterDisabled", xmlSecKeyDataKlassGetName(functions->keyData ## name ## GetKlass()));             \
        return(-1);                                                                                                                       \
    }                                                                                                                                     \

#define XMLSEC_REGISTER_TRANSFORM(name)     \
    if((functions->transform ## name ## GetKlass != NULL) && xmlSecTransformIdsRegister(functions->transform ## name ## GetKlass()) < 0) {   \
        xmlSecInternalError("xmlSecTransformIdsRegister", xmlSecTransformKlassGetName(functions->transform ## name ## GetKlass()));          \
        return(-1);                                                                                                                          \
    }                                                                                                                                        \


/**
 * xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms:
 * @functions:          the functions table.
 *
 * Registers the key data and transforms klasses from @functions table in xmlsec.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms(struct _xmlSecCryptoDLFunctions* functions) {
    xmlSecAssert2(functions != NULL, -1);

    /****************************************************************************
     *
     * Register keys
     *
     ****************************************************************************/
    XMLSEC_REGISTER_KEY_DATA(Aes);                  // keyDataAesGetKlass
    XMLSEC_REGISTER_KEY_DATA(ConcatKdf);            // keyDataConcatKdfGetKlass
    XMLSEC_REGISTER_KEY_DATA(Des);                  // keyDataDesGetKlass
    XMLSEC_REGISTER_KEY_DATA(Dh);                   // keyDataDhGetKlass
    XMLSEC_REGISTER_KEY_DATA(Dsa);                  // keyDataDsaGetKlass
    XMLSEC_REGISTER_KEY_DATA(Ec);                   // keyDataEcGetKlass
    XMLSEC_REGISTER_KEY_DATA(Gost2001);             // keyDataGost2001GetKlass
    XMLSEC_REGISTER_KEY_DATA(GostR3410_2012_256);   // keyDataGostR3410_2012_256GetKlass
    XMLSEC_REGISTER_KEY_DATA(GostR3410_2012_512);   // keyDataGetKlass
    XMLSEC_REGISTER_KEY_DATA(Hmac);                 // keyDataHmacGetKlass
    XMLSEC_REGISTER_KEY_DATA(Pbkdf2);               // keyDataPbkdf2GetKlass
    XMLSEC_REGISTER_KEY_DATA(Rsa);                  // keyDataRsaGetKlass
    XMLSEC_REGISTER_KEY_DATA(X509);                 // keyDataX509GetKlass
    XMLSEC_REGISTER_KEY_DATA(RawX509Cert);          // keyDataRawX509CertGetKlass

     /* DEREncodedKeyValue key data should not be used in production w/o understanding of the security risks */
    XMLSEC_REGISTER_DISABLED_KEY_DATA(DEREncodedKeyValue);   // keyDataDEREncodedKeyValueGetKlass


    /****************************************************************************
     *
     * Register transforms
     *
     ****************************************************************************/
    XMLSEC_REGISTER_TRANSFORM(Aes128Cbc);                           // transformAes128CbcGetKlass
    XMLSEC_REGISTER_TRANSFORM(Aes192Cbc);                           // transformAes192CbcGetKlass
    XMLSEC_REGISTER_TRANSFORM(Aes192Cbc);                           // transformAes192CbcGetKlass
    XMLSEC_REGISTER_TRANSFORM(Aes256Cbc);                           // transformAes256CbcGetKlass

    XMLSEC_REGISTER_TRANSFORM(Aes128Gcm);                           // transformAes128GcmGetKlass
    XMLSEC_REGISTER_TRANSFORM(Aes192Gcm);                           // transformAes192GcmGetKlass
    XMLSEC_REGISTER_TRANSFORM(Aes256Gcm);                           // transformAes256GcmGetKlass

    XMLSEC_REGISTER_TRANSFORM(ConcatKdf);                           // transformConcatKdfGetKlass

    XMLSEC_REGISTER_TRANSFORM(KWAes128);                            // transformKWAes128GetKlass
    XMLSEC_REGISTER_TRANSFORM(KWAes192);                            // transformKWAes192GetKlass
    XMLSEC_REGISTER_TRANSFORM(KWAes256);                            // transformKWAes256GetKlass

    XMLSEC_REGISTER_TRANSFORM(Des3Cbc);                             // transformDes3CbcGetKlass

    XMLSEC_REGISTER_TRANSFORM(KWDes3);                              // transformKWDes3GetKlass

    XMLSEC_REGISTER_TRANSFORM(Gost2001GostR3411_94);                // transformGost2001GostR3411_94GetKlass
    XMLSEC_REGISTER_TRANSFORM(GostR3410_2012GostR3411_2012_256);    // transformGostR3410_2012GostR3411_2012_256GetKlass
    XMLSEC_REGISTER_TRANSFORM(GostR3410_2012GostR3411_2012_512);    // transformGostR3410_2012GostR3411_2012_512GetKlass

    XMLSEC_REGISTER_TRANSFORM(DhEs);                                // transformDhEsGetKlass

    XMLSEC_REGISTER_TRANSFORM(DsaSha1);                             // transformDsaSha1GetKlass
    XMLSEC_REGISTER_TRANSFORM(DsaSha256);                           // transformDsaSha256GetKlass

    XMLSEC_REGISTER_TRANSFORM(Ecdh);                                // transformEcdhGetKlass

    XMLSEC_REGISTER_TRANSFORM(EcdsaRipemd160);                      // transformEcdsaRipemd160GetKlass

    XMLSEC_REGISTER_TRANSFORM(EcdsaSha1);                           // transformEcdsaSha1GetKlass

    XMLSEC_REGISTER_TRANSFORM(EcdsaSha224);                         // transformEcdsaSha224GetKlass
    XMLSEC_REGISTER_TRANSFORM(EcdsaSha256);                         // transformEcdsaSha256GetKlass
    XMLSEC_REGISTER_TRANSFORM(EcdsaSha384);                         // transformEcdsaSha384GetKlass
    XMLSEC_REGISTER_TRANSFORM(EcdsaSha512);                         // transformEcdsaSha512GetKlass

    XMLSEC_REGISTER_TRANSFORM(EcdsaSha3_224);                       // transformEcdsaSha3_224GetKlass
    XMLSEC_REGISTER_TRANSFORM(EcdsaSha3_256);                       // transformEcdsaSha3_256GetKlass
    XMLSEC_REGISTER_TRANSFORM(EcdsaSha3_384);                       // transformEcdsaSha3_384GetKlass
    XMLSEC_REGISTER_TRANSFORM(EcdsaSha3_512);                       // transformEcdsaSha3_512GetKlass

    XMLSEC_REGISTER_TRANSFORM(HmacMd5);                             // transformHmacMd5GetKlass

    XMLSEC_REGISTER_TRANSFORM(HmacRipemd160);                       // transformHmacRipemd160GetKlass

    XMLSEC_REGISTER_TRANSFORM(HmacSha1);                            // transformHmacSha1GetKlass

    XMLSEC_REGISTER_TRANSFORM(HmacSha224);                          // transformHmacSha224GetKlass
    XMLSEC_REGISTER_TRANSFORM(HmacSha256);                          // transformHmacSha256GetKlass
    XMLSEC_REGISTER_TRANSFORM(HmacSha384);                          // transformHmacSha384GetKlass
    XMLSEC_REGISTER_TRANSFORM(HmacSha512);                          // transformHmacSha512GetKlass

    XMLSEC_REGISTER_TRANSFORM(Md5);                                 // transformMd5GetKlass

    XMLSEC_REGISTER_TRANSFORM(Pbkdf2);                              // transformPbkdf2GetKlass

    XMLSEC_REGISTER_TRANSFORM(Ripemd160);                           // transformRipemd160GetKlass

    XMLSEC_REGISTER_TRANSFORM(RsaMd5);                              // transformRsaMd5GetKlass

    XMLSEC_REGISTER_TRANSFORM(RsaRipemd160);                        // transformRsaRipemd160GetKlass

    XMLSEC_REGISTER_TRANSFORM(RsaSha1);                             // transformRsaSha1GetKlass

    XMLSEC_REGISTER_TRANSFORM(RsaSha224);                           // transformRsaSha224GetKlass
    XMLSEC_REGISTER_TRANSFORM(RsaSha256);                           // transformRsaSha256GetKlass
    XMLSEC_REGISTER_TRANSFORM(RsaSha384);                           // transformRsaSha384GetKlass
    XMLSEC_REGISTER_TRANSFORM(RsaSha512);                           // transformRsaSha512GetKlass

    XMLSEC_REGISTER_TRANSFORM(RsaPssSha1);                          // transformRsaPssSha1GetKlass

    XMLSEC_REGISTER_TRANSFORM(RsaPssSha224);                        // transformRsaPssSha224GetKlass
    XMLSEC_REGISTER_TRANSFORM(RsaPssSha256);                        // transformRsaPssSha256GetKlass
    XMLSEC_REGISTER_TRANSFORM(RsaPssSha384);                        // transformRsaPssSha384GetKlass
    XMLSEC_REGISTER_TRANSFORM(RsaPssSha512);                        // transformRsaPssSha512GetKlass

    XMLSEC_REGISTER_TRANSFORM(RsaPssSha3_224);                      // transformRsaPssSha3_224GetKlass
    XMLSEC_REGISTER_TRANSFORM(RsaPssSha3_256);                      // transformRsaPssSha3_256GetKlass
    XMLSEC_REGISTER_TRANSFORM(RsaPssSha3_384);                      // transformRsaPssSha3_384GetKlass
    XMLSEC_REGISTER_TRANSFORM(RsaPssSha3_512);                      // transformRsaPssSha3_512GetKlass

    XMLSEC_REGISTER_TRANSFORM(RsaPkcs1);                            // transformRsaPkcs1GetKlass

    XMLSEC_REGISTER_TRANSFORM(RsaOaep);                             // transformRsaOaepGetKlass
    XMLSEC_REGISTER_TRANSFORM(RsaOaepEnc11);                        // transformRsaOaepEnc11GetKlass

    XMLSEC_REGISTER_TRANSFORM(GostR3411_94);                        // transformGostR3411_94GetKlass
    XMLSEC_REGISTER_TRANSFORM(GostR3411_2012_256);                  // transformGostR3411_2012_256GetKlass
    XMLSEC_REGISTER_TRANSFORM(GostR3411_2012_512);                  // transformGostR3411_2012_512GetKlass

    XMLSEC_REGISTER_TRANSFORM(Sha1);                                // transformSha1GetKlass

    XMLSEC_REGISTER_TRANSFORM(Sha224);                              // transformSha224GetKlass
    XMLSEC_REGISTER_TRANSFORM(Sha256);                              // transformSha256GetKlass
    XMLSEC_REGISTER_TRANSFORM(Sha384);                              // transformSha384GetKlass
    XMLSEC_REGISTER_TRANSFORM(Sha512);                              // transformSha512GetKlass

    XMLSEC_REGISTER_TRANSFORM(Sha3_224);                            // transformSha3_224GetKlass
    XMLSEC_REGISTER_TRANSFORM(Sha3_256);                            // transformSha3_256GetKlass
    XMLSEC_REGISTER_TRANSFORM(Sha3_384);                            // transformSha3_384GetKlass
    XMLSEC_REGISTER_TRANSFORM(Sha3_512);                            // transformSha3_512GetKlass

    /* done */
    return(0);
}
