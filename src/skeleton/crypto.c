/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

/* TODO: add Skeleton include files */

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/skeleton/crypto.h>

static int		xmlSecSkeletonKeysInit			(void);
static int		xmlSecSkeletonTransformsInit		(void);

/**
 * xmlSecSkeletonInit:
 * 
 * XMLSec library specific crypto engine initialization. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecSkeletonInit (void)  {
    /* TODO: if necessary do, additional initialization here */
    
    if(xmlSecSkeletonKeysInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecSkeletonKeysInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    if(xmlSecSkeletonTransformsInit() < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecSkeletonTransformsInit",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    
    return(0);
}

/**
 * xmlSecSkeletonShutdown:
 * 
 * XMLSec library specific crypto engine shutdown. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int 
xmlSecSkeletonShutdown(void) {
    /* TODO: if necessary, do additional shutdown here */
    return(0);
}

/**
 * xmlSecSkeletonKeysMngrInit:
 * @mngr:		the pointer to keys manager.
 *
 * Adds Skeleton specific key data stores in keys manager.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecSkeletonKeysMngrInit(xmlSecKeysMngrPtr mngr) {
    xmlSecAssert2(mngr != NULL, -1);

    /* TODO: add key data stores */
    return(0);
}

/**
 * xmlSecSkeletonGenerateRandom:
 * @buffer:		the destination buffer.
 * @size:		the numer of bytes to generate.
 *
 * Generates @size random bytes and puts result in @buffer
 * (not implemented yet).
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecSkeletonGenerateRandom(xmlSecBufferPtr buffer, size_t size) {	
    int ret;
    
    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(size > 0, -1);

    ret = xmlSecBufferSetSize(buffer, size);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    NULL,
		    "xmlSecBufferSetSize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "size=%d", size);
	return(-1);
    }
        
    /* TODO: get random data */
    xmlSecError(XMLSEC_ERRORS_HERE,
		NULL,
		"xmlSecSkeletonGenerateRandom",
		XMLSEC_ERRORS_R_NOT_IMPLEMENTED,
		XMLSEC_ERRORS_NO_MESSAGE);
    return(0);
}


static int		
xmlSecSkeletonKeysInit(void) {
    /* TODO: register key data here */
    return(0);
}

static int 
xmlSecSkeletonTransformsInit(void) {
    /* TODO: register transforms here */
    return(0);
}

