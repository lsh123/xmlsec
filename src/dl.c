/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
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
#include <xmlsec/errors.h>
#include <xmlsec/dl.h>

#ifndef XMLSEC_NO_CRYPTO_DYNAMIC_LOADING

#ifdef _MSC_VER
#include <windows.h>
#else /* _MSC_VER */
#include "xmlsec-ltdl.h"
#endif /* _MSC_VER */

#if defined(_MSC_VER)
#define snprintf _snprintf
#endif

/***********************************************************************
 *
 * loaded libraries list
 *
 **********************************************************************/
typedef struct _xmlSecCryptoDLLibrary					xmlSecCryptoDLLibrary,
									*xmlSecCryptoDLLibraryPtr;
struct _xmlSecCryptoDLLibrary {
    xmlChar*	name;
    xmlChar* 	filename;
    xmlChar* 	getFunctionsName;
    xmlSecCryptoDLFunctionsPtr functions;

#ifdef _MSC_VER
    HMODULE 	handle;
#else /* _MSC_VER */
    xmlsec_lt_dlhandle handle;
#endif /* _MSC_VER */
};

static xmlSecCryptoDLLibraryPtr	xmlSecCryptoDLLibraryCreate		(const xmlChar* name);
static void			xmlSecCryptoDLLibraryDestroy		(xmlSecCryptoDLLibraryPtr lib);
static xmlSecCryptoDLLibraryPtr	xmlSecCryptoDLLibraryDuplicate		(xmlSecCryptoDLLibraryPtr lib);
static xmlChar*			xmlSecCryptoDLLibraryConstructFilename	(const xmlChar* name);
static xmlChar*			xmlSecCryptoDLLibraryConstructGetFunctionsName(const xmlChar* name);
							

static xmlSecPtrListKlass xmlSecCryptoDLLibrariesListKlass = {
    BAD_CAST "dl-libraries-list",
    (xmlSecPtrDuplicateItemMethod)xmlSecCryptoDLLibraryDuplicate,/* xmlSecPtrDuplicateItemMethod duplicateItem; */
    (xmlSecPtrDestroyItemMethod)xmlSecCryptoDLLibraryDestroy,	/* xmlSecPtrDestroyItemMethod destroyItem; */
    NULL,							/* xmlSecPtrDebugDumpItemMethod debugDumpItem; */
    NULL,							/* xmlSecPtrDebugDumpItemMethod debugXmlDumpItem; */
};
static xmlSecPtrListId		xmlSecCryptoDLLibrariesListGetKlass	(void);
static int			xmlSecCryptoDLLibrariesListFindByName	(xmlSecPtrListPtr list, 
									 const xmlChar* name);

typedef xmlSecCryptoDLFunctionsPtr (*xmlSecCryptoGetFunctionsCallback)(void);

static xmlSecCryptoDLLibraryPtr	
xmlSecCryptoDLLibraryCreate(const xmlChar* name) {
    xmlSecCryptoDLLibraryPtr lib;
    xmlSecCryptoGetFunctionsCallback getFunctions;
    
    xmlSecAssert2(name != NULL, NULL);

    /* fprintf (stderr, "loading \"library %s\"...\n", name); */
    
    /* Allocate a new xmlSecCryptoDLLibrary and fill the fields. */
    lib = (xmlSecCryptoDLLibraryPtr)xmlMalloc(sizeof(xmlSecCryptoDLLibrary));
    if(lib == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "size=%d", sizeof(lib)); 
	return(NULL);
    }
    memset(lib, 0, sizeof(xmlSecCryptoDLLibrary));
    
    lib->name = xmlStrdup(name);
    if(lib->name == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlStrdup",
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE); 
	xmlSecCryptoDLLibraryDestroy(lib);
	return(NULL);
    }

    lib->filename = xmlSecCryptoDLLibraryConstructFilename(name);
    if(lib->filename == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlSecCryptoDLLibraryConstructFilename",
		    NULL,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE); 
	xmlSecCryptoDLLibraryDestroy(lib);
	return(NULL);
    }

    lib->getFunctionsName = xmlSecCryptoDLLibraryConstructGetFunctionsName(name);
    if(lib->getFunctionsName == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlSecCryptoDLLibraryConstructGetFunctionsName",
		    NULL,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE); 
	xmlSecCryptoDLLibraryDestroy(lib);
	return(NULL);
    }


#ifdef _MSC_VER
    lib->handle = LoadLibrary((char*)lib->filename);
    if(lib->handle == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "LoadLibrary",
		    NULL,
		    XMLSEC_ERRORS_R_IO_FAILED,
		    "filename=%s",
		    xmlSecErrorsSafeString(lib->filename));
	xmlSecCryptoDLLibraryDestroy(lib);
	return(NULL);
    }

    
    getFunctions = (xmlSecCryptoGetFunctionsCallback)GetProcAddress(lib->handle, (char*)lib->getFunctionsName);
    if(getFunctions == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "GetProcAddress",
		    NULL,
		    XMLSEC_ERRORS_R_IO_FAILED,
		    "function=%s",
		    xmlSecErrorsSafeString(lib->getFunctionsName));
	xmlSecCryptoDLLibraryDestroy(lib);
	return(NULL);
    }
#else /* _MSC_VER */
    lib->handle = xmlsec_lt_dlopen((char*)lib->filename);
    if(lib->handle == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlsec_lt_dlopen",
		    NULL,
		    XMLSEC_ERRORS_R_IO_FAILED,
		    "filename=%s",
		    xmlSecErrorsSafeString(lib->filename));
	xmlSecCryptoDLLibraryDestroy(lib);
	return(NULL);
    }

    
    getFunctions = (xmlSecCryptoGetFunctionsCallback)xmlsec_lt_dlsym(lib->handle, (char*)lib->getFunctionsName);
    if(getFunctions == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlsec_lt_dlsym",
		    NULL,
		    XMLSEC_ERRORS_R_IO_FAILED,
		    "function=%s",
		    xmlSecErrorsSafeString(lib->getFunctionsName));
	xmlSecCryptoDLLibraryDestroy(lib);
	return(NULL);
    }
#endif /* _MSC_VER */


    if(getFunctions == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "invalid configuration: no way to load library");
	xmlSecCryptoDLLibraryDestroy(lib);
	return(NULL);
    }    

    lib->functions = getFunctions();
    if(lib->functions == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "getFunctions",
		    NULL,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE); 
	xmlSecCryptoDLLibraryDestroy(lib);
	return(NULL);
    }

    /* fprintf (stderr, "library %s loaded\n", name); */
    return(lib);
}

static void 
xmlSecCryptoDLLibraryDestroy(xmlSecCryptoDLLibraryPtr lib) {
    xmlSecAssert(lib != NULL);

    fprintf (stderr, "unloading \"library %s\"...\n", lib->name); 
    if(lib->name != NULL) {
	xmlFree(lib->name);
    }

    if(lib->filename != NULL) {
	xmlFree(lib->filename);
    }
    
    if(lib->getFunctionsName != NULL) {
	xmlFree(lib->getFunctionsName);
    }

    if(lib->handle != NULL) {	
#ifdef _MSC_VER
	if(!FreeLibrary(lib->handle)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        "FreeLibrary",
			NULL,
		        XMLSEC_ERRORS_R_IO_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
	}
#else /* _MSC_VER */
	int ret;

	ret = xmlsec_lt_dlclose(lib->handle);
	if(ret != 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        "xmlsec_lt_dlclose",
			NULL,
		        XMLSEC_ERRORS_R_IO_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
	}
#endif /* _MSC_VER */
    }

    memset(lib, 0, sizeof(xmlSecCryptoDLLibrary));
    xmlFree(lib);
}

static xmlSecCryptoDLLibraryPtr	
xmlSecCryptoDLLibraryDuplicate(xmlSecCryptoDLLibraryPtr lib) {
    xmlSecAssert2(lib != NULL, NULL);
    xmlSecAssert2(lib->name != NULL, NULL);

    return(xmlSecCryptoDLLibraryCreate(lib->name));
}

static xmlChar*	
xmlSecCryptoDLLibraryConstructFilename(const xmlChar* name) {
#ifdef _MSC_VER
    static xmlChar tmpl[] = "lib%s-%s.dll";
#else /* _MSC_VER */
    static xmlChar tmpl[] = "lib%s-%s" LTDL_SHLIB_EXT;
#endif /* _MSC_VER */

    xmlChar* res;
    int len;
    
    xmlSecAssert2(name != NULL, NULL);
    
    /* TODO */
    len = xmlStrlen(BAD_CAST PACKAGE) + xmlStrlen(name) + xmlStrlen(tmpl) + 1;
    res = (xmlChar*)xmlMalloc(len + 1);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "size=%d", len + 1); 
	return(NULL);
    }
    snprintf(res, len, tmpl, PACKAGE, name);
    
    return(res);
}

static xmlChar*	
xmlSecCryptoDLLibraryConstructGetFunctionsName(const xmlChar* name) {
    static xmlChar tmpl[] = "xmlSecCryptoGetFunctions_%s";
    xmlChar* res;
    int len;
    
    xmlSecAssert2(name != NULL, NULL);
    
    len = xmlStrlen(name) + xmlStrlen(tmpl) + 1;
    res = (xmlChar*)xmlMalloc(len + 1);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "size=%d", len + 1); 
	return(NULL);
    }
    snprintf(res, len, tmpl, name);
    
    return(res);
}

static xmlSecPtrListId 
xmlSecCryptoDLLibrariesListGetKlass(void) {
    return(&xmlSecCryptoDLLibrariesListKlass);
}

static int
xmlSecCryptoDLLibrariesListFindByName(xmlSecPtrListPtr list, const xmlChar* name) {
    xmlSecSize i, size;
    xmlSecCryptoDLLibraryPtr lib;
    
    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecCryptoDLLibrariesListGetKlass()), -1);
    xmlSecAssert2(name != NULL, -1);
    
    size = xmlSecPtrListGetSize(list);
    for(i = 0; i < size; ++i) {
	lib = (xmlSecCryptoDLLibraryPtr)xmlSecPtrListGetItem(list, i);
	if((lib != NULL) && (lib->name != NULL) && (xmlStrcmp(lib->name, name) == 0)) {
	    return(i);
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

int 
xmlSecCryptoDLInit(void) {
    int ret;
    
    ret = xmlSecPtrListInitialize(&gXmlSecCryptoDLLibraries, xmlSecCryptoDLLibrariesListGetKlass());
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecPtrListPtrInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecCryptoDLLibrariesListGetKlass");
        return(-1);
    }

#ifdef _MSC_VER
#else /* _MSC_VER */
    ret = xmlsec_lt_dlinit ();
    if(ret != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlsec_lt_dlinit",
		    XMLSEC_ERRORS_R_IO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    /* TODO: LTDL_SET_PRELOADED_SYMBOLS(); */
#endif /* _MSC_VER */

    return(0);
}

int 
xmlSecCryptoDLShutdown(void) {
    int ret;
    
    xmlSecPtrListFinalize(&gXmlSecCryptoDLLibraries);

#ifdef _MSC_VER
#else /* _MSC_VER */
    ret = xmlsec_lt_dlexit ();
    if(ret != 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlsec_lt_dlexit",
		    XMLSEC_ERRORS_R_IO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
    }
#endif /* _MSC_VER */
    return(0);
}

/** 
 * xmlSecCryptoDLLoadLibrary:
 * @crypto:		the desired crypto library name ("openssl", "nss", ...).
 *
 * Loads the xmlsec-<crypto> library. This function is NOT thread safe, 
 * application MUST NOT call #xmlSecCryptoDLLoadLibrary, #xmlSecCryptoDLGetLibraryFunctions,
 * and #xmlSecCryptoDLUnloadLibrary functions from multiple threads.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecCryptoDLLoadLibrary(const xmlChar* crypto) {
    xmlSecCryptoDLFunctionsPtr functions;
    int ret;
    
    xmlSecAssert2(crypto != NULL, -1);

    functions = xmlSecCryptoDLGetLibraryFunctions(crypto);
    if(functions == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
	    	    NULL,
		    "xmlSecCryptoDLGetLibraryFunctions",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    ret = xmlSecCryptoDLSetFunctions(functions);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
	    	    NULL,
		    "xmlSecCryptoDLSetFunctions",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

/** 
 * xmlSecCryptoDLGetLibraryFunctions:
 * @crypto:		the desired crypto library name ("openssl", "nss", ...).
 *
 * Loads the xmlsec-<crypto> library and gets global crypto functions/transforms/keys data/keys store 
 * table. This function is NOT thread safe, application MUST NOT call #xmlSecCryptoDLLoadLibrary, 
 * #xmlSecCryptoDLGetLibraryFunctions, and #xmlSecCryptoDLUnloadLibrary functions from multiple threads.
 *
 * Returns the table or NULL if an error occurs.
 */
xmlSecCryptoDLFunctionsPtr 
xmlSecCryptoDLGetLibraryFunctions(const xmlChar* crypto) {
    xmlSecCryptoDLLibraryPtr lib;
    int pos;
    int ret;
        
    xmlSecAssert2(crypto != NULL, NULL);

    pos = xmlSecCryptoDLLibrariesListFindByName(&gXmlSecCryptoDLLibraries, crypto);
    if(pos >= 0) {
        lib = (xmlSecCryptoDLLibraryPtr)xmlSecPtrListGetItem(&gXmlSecCryptoDLLibraries, pos);
	xmlSecAssert2(lib != NULL, NULL);
	xmlSecAssert2(lib->functions != NULL, NULL);
	
	return(lib->functions);
    }

    lib = xmlSecCryptoDLLibraryCreate(crypto);
    if(lib == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
	    	    NULL,
		    "xmlSecCryptoDLLibraryCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "crypto=%s",
		    xmlSecErrorsSafeString(crypto));
	return(NULL);
    }

    ret = xmlSecPtrListAdd(&gXmlSecCryptoDLLibraries, lib);    
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
	    	    NULL,
		    "xmlSecPtrListAdd",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "crypto=%s",
		    xmlSecErrorsSafeString(crypto));
	xmlSecCryptoDLLibraryDestroy(lib);
	return(NULL);
    }

    return(lib->functions);
}

/** 
 * xmlSecCryptoDLUnloadLibrary:
 * @crypto:		the desired crypto library name ("openssl", "nss", ...).
 *
 * Unloads the xmlsec-<crypto> library. All pointers to this library
 * functions tables became invalid. This function is NOT thread safe, 
 * application MUST NOT call #xmlSecCryptoDLLoadLibrary, #xmlSecCryptoDLGetLibraryFunctions,
 * and #xmlSecCryptoDLUnloadLibrary functions from multiple threads.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecCryptoDLUnloadLibrary(const xmlChar* crypto) {
    xmlSecCryptoDLLibraryPtr lib;
    int pos;
    int ret;
    
    xmlSecAssert2(crypto != NULL, -1);

    pos = xmlSecCryptoDLLibrariesListFindByName(&gXmlSecCryptoDLLibraries, crypto);
    if(pos < 0) {
	/* todo: is it an error? */
	return(0);
    }
    
    lib = (xmlSecCryptoDLLibraryPtr)xmlSecPtrListGetItem(&gXmlSecCryptoDLLibraries, pos);
    if((lib != NULL) && (lib->functions == gXmlSecCryptoDLFunctions)) {
	gXmlSecCryptoDLFunctions = NULL;
    }
    
    ret = xmlSecPtrListRemove(&gXmlSecCryptoDLLibraries, pos);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
	    	    NULL,
		    "xmlSecPtrListRemove",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    return(0);
}

/** 
 * xmlSecCryptoDLSetFunctions:
 * @functions:		the new table
 *
 * Sets global crypto functions/transforms/keys data/keys store table.
 *
 * Returns 0 on success or a negative value if an error occurs.
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
 * Returns the table.
 */
xmlSecCryptoDLFunctionsPtr 
xmlSecCryptoDLGetFunctions(void) {
    return(gXmlSecCryptoDLFunctions);
}

#endif /* XMLSEC_NO_CRYPTO_DYNAMIC_LOADING */

/**
 * xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms:
 * @functions: 		the functions table.
 * 
 * Registers the key data and transforms klasses from @functions table in xmlsec. 
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecCryptoDLFunctionsRegisterKeyDataAndTransforms(struct _xmlSecCryptoDLFunctions* functions) {
    xmlSecAssert2(functions != NULL, -1);

    /** 
     * Register keys
     */
    if((functions->keyDataAesGetKlass != NULL) && (xmlSecKeyDataIdsRegister(functions->keyDataAesGetKlass()) < 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(functions->keyDataAesGetKlass())),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if((functions->keyDataDesGetKlass != NULL) && (xmlSecKeyDataIdsRegister(functions->keyDataDesGetKlass()) < 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(functions->keyDataDesGetKlass())),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if((functions->keyDataDsaGetKlass != NULL) && (xmlSecKeyDataIdsRegister(functions->keyDataDsaGetKlass()) < 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(functions->keyDataDsaGetKlass())),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if((functions->keyDataHmacGetKlass != NULL) && (xmlSecKeyDataIdsRegister(functions->keyDataHmacGetKlass()) < 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(functions->keyDataHmacGetKlass())),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if((functions->keyDataRsaGetKlass != NULL) && (xmlSecKeyDataIdsRegister(functions->keyDataRsaGetKlass()) < 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(functions->keyDataRsaGetKlass())),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if((functions->keyDataX509GetKlass != NULL) && (xmlSecKeyDataIdsRegister(functions->keyDataX509GetKlass()) < 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(functions->keyDataX509GetKlass())),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if((functions->keyDataRawX509CertGetKlass != NULL) && (xmlSecKeyDataIdsRegister(functions->keyDataRawX509CertGetKlass()) < 0)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(functions->keyDataRawX509CertGetKlass())),
		    "xmlSecKeyDataIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }


    /** 
     * Register transforms
     */
    if((functions->transformAes128CbcGetKlass != NULL) && xmlSecTransformIdsRegister(functions->transformAes128CbcGetKlass()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(functions->transformAes128CbcGetKlass())),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    

    if((functions->transformAes192CbcGetKlass != NULL) && xmlSecTransformIdsRegister(functions->transformAes192CbcGetKlass()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(functions->transformAes192CbcGetKlass())),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    

    if((functions->transformAes256CbcGetKlass != NULL) && xmlSecTransformIdsRegister(functions->transformAes256CbcGetKlass()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(functions->transformAes256CbcGetKlass())),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    

    if((functions->transformKWAes128GetKlass != NULL) && xmlSecTransformIdsRegister(functions->transformKWAes128GetKlass()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(functions->transformKWAes128GetKlass())),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    

    if((functions->transformKWAes192GetKlass != NULL) && xmlSecTransformIdsRegister(functions->transformKWAes192GetKlass()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(functions->transformKWAes192GetKlass())),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    

    if((functions->transformKWAes256GetKlass != NULL) && xmlSecTransformIdsRegister(functions->transformKWAes256GetKlass()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(functions->transformKWAes256GetKlass())),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    

    if((functions->transformDes3CbcGetKlass != NULL) && xmlSecTransformIdsRegister(functions->transformDes3CbcGetKlass()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(functions->transformDes3CbcGetKlass())),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    

    if((functions->transformKWDes3GetKlass != NULL) && xmlSecTransformIdsRegister(functions->transformKWDes3GetKlass()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(functions->transformKWDes3GetKlass())),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    

    if((functions->transformDsaSha1GetKlass != NULL) && xmlSecTransformIdsRegister(functions->transformDsaSha1GetKlass()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(functions->transformDsaSha1GetKlass())),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    

    if((functions->transformHmacSha1GetKlass != NULL) && xmlSecTransformIdsRegister(functions->transformHmacSha1GetKlass()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(functions->transformHmacSha1GetKlass())),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    

    if((functions->transformHmacRipemd160GetKlass != NULL) && xmlSecTransformIdsRegister(functions->transformHmacRipemd160GetKlass()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(functions->transformHmacRipemd160GetKlass())),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    

    if((functions->transformHmacMd5GetKlass != NULL) && xmlSecTransformIdsRegister(functions->transformHmacMd5GetKlass()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(functions->transformHmacMd5GetKlass())),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    

    if((functions->transformRipemd160GetKlass != NULL) && xmlSecTransformIdsRegister(functions->transformRipemd160GetKlass()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(functions->transformRipemd160GetKlass())),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    

    if((functions->transformRsaSha1GetKlass != NULL) && xmlSecTransformIdsRegister(functions->transformRsaSha1GetKlass()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(functions->transformRsaSha1GetKlass())),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    

    if((functions->transformRsaPkcs1GetKlass != NULL) && xmlSecTransformIdsRegister(functions->transformRsaPkcs1GetKlass()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(functions->transformRsaPkcs1GetKlass())),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    

    if((functions->transformRsaOaepGetKlass != NULL) && xmlSecTransformIdsRegister(functions->transformRsaOaepGetKlass()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(functions->transformRsaOaepGetKlass())),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    

    if((functions->transformSha1GetKlass != NULL) && xmlSecTransformIdsRegister(functions->transformSha1GetKlass()) < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(functions->transformSha1GetKlass())),
		    "xmlSecTransformIdsRegister",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    

    return(0);     
}


