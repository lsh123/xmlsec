/** 
 * XML Security Library 
 *
 * Keys Manager
 * 
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Cordys systems
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <libxml/tree.h>
#include <libxml/parser.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/list.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/errors.h>


/****************************************************************************
 *
 * MS Certificate Store
 * 
 * keys list (xmlSecPtrList) is located after xmlSecKeyStore
 *
 ***************************************************************************/
#define xmlSecMSCertStoreSize \
	(sizeof(xmlSecKeyStore) + sizeof(xmlSecPtrList))
#define xmlSecMSCertStoreGetList(store) \
    ((xmlSecKeyStoreCheckSize((store), xmlSecMSCertStoreSize)) ? \
	(xmlSecPtrListPtr)(((unsigned char*)(store)) + sizeof(xmlSecKeyStore)) : \
	(xmlSecPtrListPtr)NULL)

static int			xmlSecMSCertStoreInitialize	(xmlSecKeyStorePtr store);
static void			xmlSecMSCertStoreFinalize	(xmlSecKeyStorePtr store);
static xmlSecKeyPtr 		xmlSecMSCertStoreFindKey	(xmlSecKeyStorePtr store, 
								 const xmlChar* name, 
								 xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyStoreKlass xmlSecMSCertStoreKlass = {
    sizeof(xmlSecKeyStoreKlass),
    xmlSecMSCertStoreSize,

    /* data */
    BAD_CAST "ms-certificate-store",		/* const xmlChar* name; */ 
        
    /* constructors/destructor */
    xmlSecMSCertStoreInitialize,		/* xmlSecKeyStoreInitializeMethod initialize; */
    xmlSecMSCertStoreFinalize,		/* xmlSecKeyStoreFinalizeMethod finalize; */
    xmlSecMSCertStoreFindKey,		/* xmlSecKeyStoreFindKeyMethod findKey; */

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/**
 * xmlSecSimpleKeysStoreGetKlass:
 * 
 * The simple list based keys store klass.
 *
 * Returns simple list based keys store klass.
 */
xmlSecKeyStoreId 
xmlSecMSCertStoreGetKlass(void) {
    return(&xmlSecMSCertStoreKlass);
}

static int
xmlSecMSCertStoreInitialize(xmlSecKeyStorePtr store) {
    xmlSecPtrListPtr list;
    int ret;

	
	
	/*
    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecSimpleKeysStoreId), -1);

    list = 0; //xmlSecSimpleKeysStoreGetList(store);
    xmlSecAssert2(list != NULL, -1);
    
    ret = xmlSecPtrListInitialize(list, xmlSecKeyPtrListId);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
		    "xmlSecPtrListInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyPtrListId");
	return(-1);
    }
*/
    return(0);    
}

static void
xmlSecMSCertStoreFinalize(xmlSecKeyStorePtr store) {
    xmlSecPtrListPtr list;
    
    xmlSecAssert(xmlSecKeyStoreCheckId(store, xmlSecSimpleKeysStoreId));
    
    list = 0; //xmlSecSimpleKeysStoreGetList(store);
    xmlSecAssert(list != NULL);
    
    xmlSecPtrListFinalize(list);
}

static xmlSecKeyPtr 
xmlSecMSCertStoreFindKey(xmlSecKeyStorePtr store, const xmlChar* name, 
			    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecPtrListPtr list;
    xmlSecKeyPtr key;
    size_t pos, size;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecSimpleKeysStoreId), NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    list = 0; //xmlSecSimpleKeysStoreGetList(store);
    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecKeyPtrListId), NULL);

    size = xmlSecPtrListGetSize(list);
    for(pos = 0; pos < size; ++pos) {
	key = (xmlSecKeyPtr)xmlSecPtrListGetItem(list, pos);
	if((key != NULL) && (xmlSecKeyMatch(key, name, &(keyInfoCtx->keyReq)) == 1)) {
	    return(xmlSecKeyDuplicate(key));
	}
    }
    return(NULL);
}

