#include <xmlsec/base64.h>
#include <xmlsec/membuf.h>
#include <xmlsec/io.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/parser.h>

const xmlChar xmlSecEncTypeElement[] = "http://www.w3.org/2001/04/xmlenc#Element";
const xmlChar xmlSecEncTypeContent[] = "http://www.w3.org/2001/04/xmlenc#Content";

/* The ID attribute in XMLEnc is 'Id' */
static const xmlChar*		xmlSecEncIds[] = { BAD_CAST "Id", NULL };

typedef struct _xmlSecEncState {
    xmlSecEncOldCtxPtr		ctx;
    xmlSecTransformPtr 	first;
    xmlSecTransformPtr	last;
    xmlNodePtr			cipherDataNode;
    int				encrypt;
    xmlChar 			*type;
    
} xmlSecEncState, *xmlSecEncStatePtr;

/** 
 * XML Enc state
 */
static xmlSecEncStatePtr	xmlSecEncStateCreate		(xmlSecEncOldCtxPtr ctx, 
								 xmlNodePtr encNode,
								 int encrypt,
								 xmlSecEncResultPtr result);
static void			xmlSecEncStateDestroy		(xmlSecEncStatePtr state);
static int			xmlSecEncStateWriteResult	(xmlSecEncStatePtr state,
								 xmlNodePtr node,
								 xmlSecEncResultPtr result);
static int			xmlSecEncStateAddFirstTransform	(xmlSecEncStatePtr state,
								 xmlSecTransformPtr transform);
static int			xmlSecEncStateAddTransform	(xmlSecEncStatePtr state,
								 xmlSecTransformPtr transform);

#define xmlSecEncResultIsValid(result) \
	    ((( result ) != NULL) && ((result)->ctx != NULL))
#define xmlSecEncResultGetKeyCallback(result) \
	    ( ( xmlSecEncResultIsValid((result)) ) ? \
		((result)->ctx->keyInfoCtx.keysMngr->getKey) : \
		NULL )


static int			xmlSecEncryptedDataNodeRead	(xmlNodePtr encNode,
								 xmlSecEncStatePtr state, 
								 xmlSecEncResultPtr result);
static int			xmlSecCipherDataNodeRead	(xmlNodePtr cipherDataNode,
								 xmlSecEncStatePtr state, 							 
								 xmlSecEncResultPtr result);
static int 			xmlSecCipherDataNodeWrite	(xmlNodePtr cipherDataNode,
								 const unsigned char *buf,
								 size_t size);
static int			xmlSecCipherValueNodeRead	(xmlNodePtr cipherValueNode,
								 xmlSecEncStatePtr state, 
								 xmlSecEncResultPtr result);
static int			xmlSecCipherReferenceNodeRead	(xmlNodePtr cipherReferenceNode, 
								 xmlSecEncStatePtr state, 
								 xmlSecEncResultPtr result);


/****************************************************************************
 *
 * XML Encrypiton context methods
 *
 ***************************************************************************/
/**
 * xmlSecEncOldCtxCreate:
 * @keysMngr: the pointer to #xmlSecKeysMngr structure.
 * 
 * Creates new encryption context.
 *
 * Returns newly allocated #xmlSecEncOldCtx structure or NULL if an error occurs.
 */
xmlSecEncOldCtxPtr		
xmlSecEncOldCtxCreate(xmlSecKeysMngrPtr keysMngr) {
    xmlSecEncOldCtxPtr ctx;
    
    /*
     * Allocate a new xmlSecEncOldCtx and fill the fields.
     */
    ctx = (xmlSecEncOldCtxPtr) xmlMalloc(sizeof(xmlSecEncOldCtx));
    if(ctx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecEncOldCtx)=%d", 
		    sizeof(xmlSecEncOldCtx));
	return(NULL);
    }
    memset(ctx, 0, sizeof(xmlSecEncOldCtx));
    
    ctx->keyInfoCtx.keysMngr = keysMngr;
    return(ctx);
}

/**
 * xmlSecEncOldCtxDestroy:
 * @ctx: the pointer to #xmlSecEncOldCtx structure.
 *
 * Destroys the #xmlSecEncOldCtx structure.
 */
void
xmlSecEncOldCtxDestroy(xmlSecEncOldCtxPtr ctx) {
    xmlSecAssert(ctx != NULL);
    
    memset(ctx, 0, sizeof(xmlSecEncOldCtx));
    xmlFree(ctx);
}



/*************************************************************************
 *
 * Encryption functions
 *
 *************************************************************************/

/**
 * xmlSecEncryptMemory:
 * @ctx: the pointer to #xmlSecEncOldCtx structure.
 * @context: the pointer to application specific data that will be 
 *     passed to all callback functions.
 * @key: the key to use (if NULL then the key specified in <dsig:KeyInfo>
 *     will be used).   
 * @encNode: the pointer to encryption template (<enc:EncryptionData> node).
 * @buf: the pointer to data to encrypt.
 * @size: the size of the data in @buf.
 * @result: the pointer where to store encryption results.
 *
 * Encrypts binary data from the @buf according to the template in the
 * <enc:EncryptionData> node. After the encrytion the result XML is in 
 * the @encNode node.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecEncryptMemory(xmlSecEncOldCtxPtr ctx, void *context, xmlSecKeyPtr key, 
		    xmlNodePtr encNode, const unsigned char *buf, size_t size,
		    xmlSecEncResultPtr *result) {
    xmlSecTransformCtx transformCtx; /* todo */
    xmlSecEncStatePtr state = NULL;
    xmlSecEncResultPtr res = NULL;
    int ret;

    xmlSecAssert2(encNode != NULL, -1);
    xmlSecAssert2(ctx != NULL, -1);    
    xmlSecAssert2(buf != NULL, -1);    
    
    res = xmlSecEncResultCreate(ctx, context, 1, encNode);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncResultCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	    		
    }
    if(key != NULL) {
	res->key = xmlSecKeyDuplicate(key);    
    }
    
    /* add ids for Encrypted nodes */
    xmlSecAddIDs(encNode->doc, encNode, xmlSecEncIds);
    
    /**
     * create state
     */    
    state = xmlSecEncStateCreate(ctx, encNode, 1, res);
    if(state == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncStateCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecEncResultDestroy(res);
	return(-1);	    
    }
         
    /* encrypt the data */
    ret = xmlSecTransformPushBin(state->first, buf, size, 1, &transformCtx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformPushBin",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformGetName(state->first)));
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    
	return(-1);	    	
    }

    ret = xmlSecEncStateWriteResult(state, encNode, res); 			
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncStateWriteResult",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecEncStateDestroy(state);
	xmlSecEncResultDestroy(res); 
	return(-1);	    
    }
    
    /* cleanup */
    if(result != NULL) {
	(*result) = res;
    } else {
	xmlSecEncResultDestroy(res);
    }
    xmlSecEncStateDestroy(state);    
    return(0);
}

/**
 * xmlSecEncryptUri:
 * @ctx: the pointer to #xmlSecEncOldCtx structure.
 * @context: the pointer to application specific data that will be 
 *     passed to all callback functions.
 * @key: the key to use (if NULL then the key specified in <dsig:KeyInfo>
 *     will be used).   
 * @encNode: the pointer to encryption template (<enc:EncryptionData> node).
 * @uri: the URI to data to encrypt.
 * @result: the pointer where to store encryption results.
 *
 * Encrypts binary data from the @uri according to the template in the
 * <enc:EncryptionData> node. After the encrytion the result XML is in 
 * the @encNode node.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecEncryptUri(xmlSecEncOldCtxPtr ctx, void *context, xmlSecKeyPtr key, 
		xmlNodePtr encNode, const char *uri, 
		xmlSecEncResultPtr *result) {
    xmlSecTransformCtx transformCtx;
    xmlSecEncStatePtr state = NULL;
    xmlSecEncResultPtr res = NULL;
    xmlSecTransformPtr inputUri = NULL;
    unsigned char buf[1024];
    size_t bufSize;
    int ret;

    xmlSecAssert2(encNode != NULL, -1);
    xmlSecAssert2(ctx != NULL, -1);    
    xmlSecAssert2(uri != NULL, -1);    

    res = xmlSecEncResultCreate(ctx, context, 1, encNode);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncResultCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	    		
    }
    if(key != NULL) {
	res->key = xmlSecKeyDuplicate(key);    
    }

    /* add ids for Encrypted nodes */
    xmlSecAddIDs(encNode->doc, encNode, xmlSecEncIds);

    /**
     * create state
     */    
    state = xmlSecEncStateCreate(ctx, encNode, 1, res);
    if(state == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncStateCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecEncResultDestroy(res);
	return(-1);	    
    }
    
    /* add the uri load at the beginning */
    inputUri = xmlSecTransformCreate(xmlSecTransformInputURIId, 0);
    if(inputUri == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecTransformInputURIId)));
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    
	return(-1);	
    }    
    
    ret = xmlSecTransformInputURIOpen(inputUri, uri);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformInputURIOpen",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "uri=%s",
		    xmlSecErrorsSafeString(uri));
	xmlSecTransformDestroy(inputUri, 1);	
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    
	return(-1);	
    }
    
    ret = xmlSecEncStateAddFirstTransform(state, inputUri);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncStateAddFirstTransform",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformGetName(inputUri)));
	xmlSecTransformDestroy(inputUri, 1);	
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    
	return(-1);	
    }
         
    /* encrypt the data */
    do {
	ret = xmlSecTransformPopBin(state->last, buf, sizeof(buf), &bufSize, &transformCtx);
    } while((ret >= 0) && (bufSize > 0));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformPopBin",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformGetName(state->last)));
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    
	return(-1);	    	
    }

    ret = xmlSecEncStateWriteResult(state, encNode, res); 			
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncStateWriteResult",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecEncStateDestroy(state);
	xmlSecEncResultDestroy(res); 
	return(-1);	    
    }
    
    /* cleanup */
    if(result != NULL) {
	(*result) = res;
    } else {
	xmlSecEncResultDestroy(res);
    }
    xmlSecEncStateDestroy(state);    
    return(0);
}

/**
 * xmlSecEncryptXmlNode:
 * @ctx: the pointer to #xmlSecEncOldCtx structure.
 * @context: the pointer to application specific data that will be 
 *     passed to all callback functions.
 * @key: the key to use (if NULL then the key specified in <dsig:KeyInfo>
 *     will be used).   
 * @encNode: the pointer to encryption template (<enc:EncryptionData> node).
 * @src: the pointer to XML node to encrypt.
 * @result: the pointer where to store encryption results.
 *
 * Encrypts XML data from the @encNode according to the template in the
 * <enc:EncryptionData> node. After the encrytion the result XML is in 
 * the @src node.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecEncryptXmlNode(xmlSecEncOldCtxPtr ctx, void *context, xmlSecKeyPtr key, 
		    xmlNodePtr encNode, xmlNodePtr src, 
		    xmlSecEncResultPtr *result) {
    xmlSecTransformCtx transformCtx; /* todo */
    xmlSecEncStatePtr state = NULL;
    xmlSecEncResultPtr res = NULL;
    xmlBufferPtr buffer = NULL;
    int ret;

    xmlSecAssert2(encNode != NULL, -1);
    xmlSecAssert2(ctx != NULL, -1);    
    xmlSecAssert2(src != NULL, -1);    

    res = xmlSecEncResultCreate(ctx, context, 1, encNode);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncResultCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	    		
    }
    if(key != NULL) {
	res->key = xmlSecKeyDuplicate(key);    
    }

    /* add ids for Encrypted nodes */
    xmlSecAddIDs(encNode->doc, encNode, xmlSecEncIds);

    /**
     * create state
     */    
    state = xmlSecEncStateCreate(ctx, encNode, 1, res);
    if(state == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncStateCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecEncResultDestroy(res);
	return(-1);	    
    }

    buffer = xmlBufferCreate();
    if(buffer == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlBufferCreate",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    
	return(-1);	    	
    }
    
    /** 
     * read the stuff we need to encrypt into the buffer 
     */
    if(ctx->ignoreType || (res->type == NULL)) {
	/* get the content of the node */
	xmlNodeDump(buffer, src->doc, src, 0, 0);
    } else if(xmlStrEqual(res->type, xmlSecEncTypeElement)) {
	/* get the content of the node */
	xmlNodeDump(buffer, src->doc, src, 0, 0);
    } else if(xmlStrEqual(res->type, xmlSecEncTypeContent)) {
	xmlNodePtr ptr;
	/* get the content of the nodes childs */
	ptr = src->children;
	while(ptr != NULL) {
	    xmlNodeDump(buffer, ptr->doc, ptr, 0, 0); 
	    ptr = ptr->next;
	}
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "type=\"%s\"", 
		    xmlSecErrorsSafeString(res->type));
	xmlBufferFree(buffer);
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    
	return(-1);	    	
    }
        
    /* encrypt the data */
    ret = xmlSecTransformPushBin(state->first, 
				  xmlBufferContent(buffer),
				  xmlBufferLength(buffer),
				  1,
				  &transformCtx);
    xmlBufferEmpty(buffer); 
    xmlBufferFree(buffer); 
    buffer = NULL;
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformPushBin",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
	    	    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformGetName(state->first)));
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    
	return(-1);	    	
    }

    ret = xmlSecEncStateWriteResult(state, encNode, res); 			
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncStateWriteResult",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecEncStateDestroy(state);
	xmlSecEncResultDestroy(res); 
	return(-1);	    
    }
    
    if(!ctx->ignoreType && (res->type != NULL)) {
	if(xmlStrEqual(res->type, xmlSecEncTypeElement)) {
	    ret = xmlSecReplaceNode(src, encNode);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlSecReplaceNode",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "node=%s",
			    xmlSecErrorsSafeString(xmlSecNodeGetName(src)));
		xmlSecEncStateDestroy(state);
		xmlSecEncResultDestroy(res); 
		return(-1);
	    }
	    res->replaced = 1;			       
	} else if(xmlStrEqual(res->type, xmlSecEncTypeContent)) {
	    ret = xmlSecReplaceContent(src, encNode);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlSecReplaceContent",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "node=%s",
			    xmlSecErrorsSafeString(xmlSecNodeGetName(src)));
		xmlSecEncStateDestroy(state);
		xmlSecEncResultDestroy(res); 
		return(-1);
	    }
	    res->replaced = 1;			       
	} else {
	    /* do nothing: type is unknown */
	}
    }
    
    /* cleanup */
    if(result != NULL) {
	(*result) = res;
    } else {
	xmlSecEncResultDestroy(res);
    }
    xmlSecEncStateDestroy(state);    
    return(0);
}

/************************************************************************
 *
 * Decryption function
 *
 ***********************************************************************/
 
/**
 * xmlSecDecrypt:
 * @ctx: the pointer to #xmlSecEncOldCtx structure.
 * @context: the pointer to application specific data that will be 
 *     passed to all callback functions.
 * @key: the key to use (if NULL then the key specified in <dsig:KeyInfo>
 *     will be used).   
 * @encNode: the pointer to encryption template (<enc:EncryptionData> node).
 * @result: the pointer where to store encryption results.
 *
 * Decrypts data from the <enc:EncryptionData> node. 
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecDecrypt(xmlSecEncOldCtxPtr ctx, void *context, xmlSecKeyPtr key, 
	     xmlNodePtr encNode, xmlSecEncResultPtr *result) {
    xmlSecEncStatePtr state;
    xmlSecEncResultPtr res;
    int ret;

    xmlSecAssert2(encNode != NULL, -1);
    xmlSecAssert2(ctx != NULL, -1);    

    /* first of all, create result and encryption state objects */
    res = xmlSecEncResultCreate(ctx, context, 0, encNode);
    if(res == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncResultCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	    		
    }
    if(key != NULL) {
	res->key = xmlSecKeyDuplicate(key);    
    }

    /* add ids for Encrypted nodes */
    xmlSecAddIDs(encNode->doc, encNode, xmlSecEncIds);

    state = xmlSecEncStateCreate(ctx, encNode, 0, res);
    if(state == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncStateCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecEncResultDestroy(res);
	return(-1);	    
    }
    
    if(state->cipherDataNode == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "CipherData",
		    XMLSEC_ERRORS_R_NODE_NOT_FOUND,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    	
	return(-1);	    	
    }
    
    ret = xmlSecCipherDataNodeRead(state->cipherDataNode, state, res);
    if((ret < 0) || (res->buffer == NULL)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCipherDataNodeRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecEncResultDestroy(res);
	xmlSecEncStateDestroy(state);    	
	return(-1);	    	
    }
    
    if(!ctx->ignoreType && (res->type != NULL)) {
	if(xmlStrEqual(res->type, xmlSecEncTypeElement)) {
	    ret = xmlSecReplaceNodeBuffer(encNode, 
				    xmlSecBufferGetData(res->buffer),  
				    xmlSecBufferGetSize(res->buffer));
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlSecReplaceNodeBuffer",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "node=%s",
			    xmlSecErrorsSafeString(xmlSecNodeGetName(encNode)));
		xmlSecEncResultDestroy(res);
		xmlSecEncStateDestroy(state);    
		return(-1);	    	
	    }
	    res->replaced = 1;			       
	} else if(xmlStrEqual(res->type, xmlSecEncTypeContent)) {
	    /* replace the node with the buffer */
	    ret = xmlSecReplaceNodeBuffer(encNode, 
				       xmlSecBufferGetData(res->buffer),
				       xmlSecBufferGetSize(res->buffer));
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlSecReplaceNodeBuffer",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "node=%s",
			    xmlSecErrorsSafeString(xmlSecNodeGetName(encNode)));
		xmlSecEncResultDestroy(res);
		xmlSecEncStateDestroy(state);    
		return(-1);	    	
	    }	
	    res->replaced = 1;			       
	} else {
	    /* do nothing: type is unknown */
	}
    }
    
    /* cleanup */
    if(result != NULL) {
	(*result) = res;
    } else {
	xmlSecEncResultDestroy(res);
    }
    xmlSecEncStateDestroy(state);    
    return(0);
}
							 
/*************************************************************************
 *
 * XMLS Enc state
 *
 ************************************************************************/

/** 
 * xmlSecEncStateCreate:
 */ 
static xmlSecEncStatePtr
xmlSecEncStateCreate(xmlSecEncOldCtxPtr ctx, xmlNodePtr encNode, int encrypt, xmlSecEncResultPtr result) {
    xmlSecEncStatePtr state;
    int ret;

    xmlSecAssert2(encNode != NULL, NULL);
    xmlSecAssert2(ctx != NULL, NULL);    
    xmlSecAssert2(result != NULL, NULL);    
    
    /*
     * Allocate a new xmlSecEncState and fill the fields.
     */
    state = (xmlSecEncStatePtr) xmlMalloc(sizeof(xmlSecEncState));
    if(state == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecEncState)=%d", 
		    sizeof(xmlSecEncState));
	return(NULL);
    }
    memset(state, 0, sizeof(xmlSecEncState));
        
    state->encrypt = encrypt;
    state->ctx = ctx;

    /*  read and update the Encryption Method and KeyInfo */
    ret = xmlSecEncryptedDataNodeRead(encNode, state, result);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncryptedDataNodeRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecEncStateDestroy(state);
	return(NULL);	    	
    }

    return(state);
}

/** 
 * xmlSecEncStateDestroy:
 */ 
static void
xmlSecEncStateDestroy(xmlSecEncStatePtr state) {
    xmlSecAssert(state != NULL);

    if(state->first != NULL) {
	xmlSecTransformDestroyAll((xmlSecTransformPtr)state->first);
    } else if(state->last != NULL) {
	xmlSecTransformDestroyAll((xmlSecTransformPtr)state->last);
    }
    
    memset(state, 0, sizeof(xmlSecEncState));
    xmlFree(state);
}

/**
 * xmlSecEncStateWriteResult:
 */
static int
xmlSecEncStateWriteResult(xmlSecEncStatePtr state, xmlNodePtr encNode,
		       xmlSecEncResultPtr result) {
    int ret;
    
    xmlSecAssert2(encNode != NULL, -1);
    xmlSecAssert2(state != NULL, -1);    
    xmlSecAssert2(result != NULL, -1);    

    /* update template */
    result->buffer = xmlSecTransformMemBufGetBuffer((xmlSecTransformPtr)state->last, 1);
    if(result->buffer == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformMemBufGetBuffer",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecEncResultDestroy(result);
	xmlSecEncStateDestroy(state);    
	return(-1);	    	
    }
    
    ret = xmlSecCipherDataNodeWrite(state->cipherDataNode, 
				xmlSecBufferGetData(result->buffer), 
				xmlSecBufferGetSize(result->buffer));
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecCipherDataNodeWrite",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecEncResultDestroy(result);
	xmlSecEncStateDestroy(state);    
	return(-1);	    	
    }
    return(0);
}

/**
 * xmlSecEncStateAddTransform:
 */
static int
xmlSecEncStateAddTransform(xmlSecEncStatePtr state, 
			    xmlSecTransformPtr transform) {

    xmlSecAssert2(state != NULL, -1);    
    xmlSecAssert2(transform != NULL, -1);    

    if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeBinary)) { 
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformCheckType",
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformTypeBinary");
	return(-1);	    
    }
    if(state->last == NULL) {
	state->first = state->last = (xmlSecTransformPtr)transform;
    } else if(xmlSecTransformAddAfter((xmlSecTransformPtr)state->last, 
					 transform) != NULL) {
	 state->last = (xmlSecTransformPtr)transform;
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformAddAfter",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	    
    }
    return(0);
}

/**
 * xmlSecEncStateAddFirstTransform:
 */
static int
xmlSecEncStateAddFirstTransform(xmlSecEncStatePtr state, xmlSecTransformPtr transform) {
    xmlSecAssert2(state != NULL, -1);    
    xmlSecAssert2(transform != NULL, -1);    

    if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeBinary)) { 
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformCheckType",
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformTypeBinary");
	return(-1);	    
    }
    if(state->first == NULL) {
	state->first = state->last = (xmlSecTransformPtr)transform;
    } else if(xmlSecTransformAddBefore((xmlSecTransformPtr)state->first, 
					  transform) != NULL) {
	 state->first = (xmlSecTransformPtr)transform;
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformAddBefore",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);	    
    }
    return(0);
}

/**************************************************************************
 *
 * XML Enc Result functions
 *
 *************************************************************************/
/**
 * xmlSecEncResultCreate:
 * @ctx: the pointer to #xmlSecEncOldCtx structure.
 * @context: the pointer to application specific data that will be 
 *     passed to all callback functions.
 * @encrypt: the encrypt/decrypt flag.
 * @node: the pointer to <enc:EncryptedData> node.
 * 
 * Creates new #xmlSecEncResult structure.
 *
 * Returns newly created #xmlSecEncResult structure or NULL 
 * if an error occurs.
 */ 		
xmlSecEncResultPtr		
xmlSecEncResultCreate(xmlSecEncOldCtxPtr ctx, void *context, int encrypt, xmlNodePtr node) {
    xmlSecEncResultPtr result;

    xmlSecAssert2(ctx != NULL, NULL);    
    
    /*
     * Allocate a new xmlSecEncResult and fill the fields.
     */
    result = (xmlSecEncResultPtr) xmlMalloc(sizeof(xmlSecEncResult));
    if(result == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecEncResult)=%d", 
		    sizeof(xmlSecEncResult));
	return(NULL);
    }
    memset(result, 0, sizeof(xmlSecEncResult));
        
    result->ctx = ctx;
    result->self = node;
    result->encrypt = encrypt;
    result->context = context;
    return(result);
}

/**
 * xmlSecEncResultDestroy:
 * @result: the pointer to #xmlSecEncResult structure.
 *
 * Destroys #xmlSecEncResult structure @result.
 */ 		
void
xmlSecEncResultDestroy(xmlSecEncResultPtr result) {
    xmlSecAssert(result != NULL);
    
    if(result->key != NULL) {
	xmlSecKeyDestroy(result->key);
    }

    if(result->buffer != NULL) {
	xmlSecBufferDestroy(result->buffer); 	
    }

    if(result->id != NULL) {
	xmlFree(result->id);
    }
    if(result->type != NULL) {
	xmlFree(result->type);
    }
    if(result->mimeType != NULL) {
	xmlFree(result->mimeType);
    }
    if(result->encoding != NULL) {
	xmlFree(result->encoding);
    }
    
    memset(result, 0, sizeof(xmlSecEncResult));
    xmlFree(result);
}


/**
 * xmlSecEncResultDebugDump:
 * @result: the pointer to #xmlSecEncResult structure.
 * @output: the pointer to destination FILE.
 *
 * Prints the #xmlSecEncResult structure @result to file @output.
 */
void
xmlSecEncResultDebugDump(xmlSecEncResultPtr result, FILE *output) {
    xmlSecAssert(result != NULL);
    xmlSecAssert(output != NULL);

    if(result->encrypt) {    
        fprintf(output, "= ENCRYPTION RESULT\n");
    } else {
        fprintf(output, "= DECRYPTION RESULT (%s)\n",
	    (result->replaced) ? "replaced" : "not-replaced" );
    }
    if(result->id != NULL) {
	fprintf(output, "== Id: \"%s\"\n", result->id);
    }
    if(result->type != NULL) {
	fprintf(output, "== Type: \"%s\"\n", result->type);
    }
    if(result->mimeType != NULL) {
	fprintf(output, "== MimeType: \"%s\"\n", result->mimeType);
    }
    if(result->encoding != NULL) {
	fprintf(output, "== Encoding: \"%s\"\n", result->encoding);
    }
    
    if(result->key != NULL) {
	xmlSecKeyDebugDump(result->key, output);
    }

    if(result->buffer != NULL) {
	fprintf(output, "== start buffer:\n");
	fwrite(xmlSecBufferGetData(result->buffer), 
	       xmlSecBufferGetSize(result->buffer), 1,
	       output);
	fprintf(output, "\n== end buffer\n");
    }	    

}


/**
 * xmlSecEncResultDebugXmlDump:
 * @result: the pointer to #xmlSecEncResult structure.
 * @output: the pointer to destination FILE.
 *
 * Prints the #xmlSecEncResult structure @result to file @output in XML format.
 */
void
xmlSecEncResultDebugXmlDump(xmlSecEncResultPtr result, FILE *output) {
    xmlSecAssert(result != NULL);
    xmlSecAssert(output != NULL);

    if(result->encrypt) {    
        fprintf(output, "<EncryptionResult>\n");
    } else {
        fprintf(output, "<DecryptionResult type=\"%s\">\n",
	    (result->replaced) ? "replaced" : "not-replaced" );
    }
    if(result->id != NULL) {
	fprintf(output, "<Id>%s</Id>\n", result->id);
    }
    if(result->type != NULL) {
	fprintf(output, "<Type>%s</Type>\n", result->type);
    }
    if(result->mimeType != NULL) {
	fprintf(output, "<MimeType%s</MimeType>\n", result->mimeType);
    }
    if(result->encoding != NULL) {
	fprintf(output, "<Encoding>%s</Encoding>\n", result->encoding);
    }
    
    if(result->key != NULL) {
	xmlSecKeyDebugXmlDump(result->key, output);
    }

    if(result->buffer != NULL) {
	fprintf(output, "<Buffer>");
	fwrite(xmlSecBufferGetData(result->buffer), 
	       xmlSecBufferGetSize(result->buffer), 1,
	       output);
	fprintf(output, "</Buffer>\n");
    }	    

    if(result->encrypt) {    
        fprintf(output, "</EncryptionResult>\n");
    } else {
        fprintf(output, "</DecryptionResult>\n");
    }

}

/**
 * xmlSecEncryptedDataNodeRead:
 */
static int
xmlSecEncryptedDataNodeRead(xmlNodePtr encNode, xmlSecEncStatePtr state, xmlSecEncResultPtr result) {
    xmlSecTransformCtx transformCtx; /* todo */
    xmlNodePtr cur;
    xmlNodePtr keyInfoNode = NULL;
    xmlSecTransformPtr encryptionMethod = NULL;
    int ret;

    xmlSecAssert2(encNode != NULL, -1);
    xmlSecAssert2(state!= NULL, -1);    
    xmlSecAssert2(result != NULL, -1);

    result->id = xmlGetProp(encNode, BAD_CAST "Id");
    result->type = xmlGetProp(encNode, BAD_CAST "Type");
    result->mimeType = xmlGetProp(encNode, BAD_CAST "MimeType");
    result->encoding = xmlGetProp(encNode, BAD_CAST "Encoding");
    cur = xmlSecGetNextElementNode(encNode->children);    
        
    /* first node is optional EncryptionMethod */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "EncryptionMethod", xmlSecEncNs))) {
	encryptionMethod = xmlSecTransformNodeRead(cur, xmlSecTransformUsageEncryptionMethod, &transformCtx);
	cur = xmlSecGetNextElementNode(cur->next);
    } else if((state->ctx != NULL) && (state->ctx->encryptionMethod != xmlSecTransformIdUnknown)){
	/* get encryption method from the context */
	encryptionMethod = xmlSecTransformCreate(state->ctx->encryptionMethod, 0);
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_DATA,
		    "encryption method not specified");
	return(-1);
    }
    if(encryptionMethod == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformNodeRead(EncMethod) or xmlSecTransformCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }    
    ret = xmlSecEncStateAddTransform(state, encryptionMethod);
    if(ret < 0) {    
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncStateAddTransform",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformGetName(encryptionMethod)));
	xmlSecTransformDestroy(encryptionMethod, 1); 
	return(-1);
    }
    encryptionMethod->encode = state->encrypt;
    result->encryptionMethod = encryptionMethod->id;
    
    /* next node is optional KeyInfo */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "KeyInfo", xmlSecDSigNs))) {
	keyInfoNode = cur;
	cur = xmlSecGetNextElementNode(cur->next);
    }    

    /* now we are ready to get key, KeyInfo node may be NULL! */
    if((result->key == NULL) && (xmlSecEncResultGetKeyCallback(result) != NULL)) {
	xmlSecKeyInfoCtxPtr keyInfoCtx;

	keyInfoCtx = &(result->ctx->keyInfoCtx);	
	ret = xmlSecTransformSetKeyReq(encryptionMethod, &(keyInfoCtx->keyReq));
	if(ret < 0) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformSetKeyReq",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformGetName(encryptionMethod)));
	    return(-1);
	}		
	result->key = (xmlSecEncResultGetKeyCallback(result))(keyInfoNode, keyInfoCtx);
    }    
    if(result->key == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    NULL,
		    XMLSEC_ERRORS_R_KEY_NOT_FOUND,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    ret = xmlSecTransformSetKey(encryptionMethod, result->key);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformSetKey",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformGetName(encryptionMethod)));
	return(-1);
    }
    if(result->encrypt && (keyInfoNode != NULL)) {
	/* update KeyInfo! */
	/* todo: do we want to write anything else??? */
	result->ctx->keyInfoCtx.keyReq.keyType = xmlSecKeyDataTypePublic;
	ret = xmlSecKeyInfoNodeWrite(keyInfoNode, 
		    		     result->key, 
				     &result->ctx->keyInfoCtx);
	if(ret < 0) {
    	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecKeyInfoNodeWrite",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}	
    }

    /* next is required CipherData node */
    if((cur == NULL) || (!xmlSecCheckNodeName(cur, xmlSecNodeCipherData, xmlSecEncNs))) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeCipherData));
	return(-1);
    }
    state->cipherDataNode = cur;
    cur = xmlSecGetNextElementNode(cur->next);

    /* next is optional EncryptionProperties node (we simply ignore it) */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, BAD_CAST "EncryptionProperties", xmlSecEncNs))) {
	cur = xmlSecGetNextElementNode(cur->next);
    }

    if(state->encrypt == 1) {
	xmlSecTransformPtr memBuf = NULL;	
	xmlSecTransformPtr base64;
	/* last transform for encryption is base64 encode */
	
	base64 = xmlSecTransformCreate(xmlSecTransformBase64Id, 0);
	if(base64 == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecTransformBase64Id)));
	    return(-1);
	}
	base64->encode = 1;
	
	ret = xmlSecEncStateAddTransform(state, base64);
	if(ret < 0) {    
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecEncStateAddTransform",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformGetName(base64)));
	    xmlSecTransformDestroy(base64, 1); 
	    return(-1);
	}
	
	/* add mem buf at the end */
	memBuf = xmlSecTransformCreate(xmlSecTransformMemBufId, 0);
	if(memBuf == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformCreate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecTransformMemBufId)));
	    return(-1);
	}
	ret = xmlSecEncStateAddTransform(state, memBuf);
        if(ret < 0) {    
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecEncStateAddTransform",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformGetName(memBuf)));
	    xmlSecTransformDestroy(memBuf, 1); 
	    return(-1);
	}
    }

/*    
    TODO: add support for other nodes
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    (cur->name != NULL) ? (char*)cur->name : "NULL");
	return(-1);
    }
*/        
    return(0);
}

/**
 * xmlSecCipherDataNodeRead:
 */
static int
xmlSecCipherDataNodeRead(xmlNodePtr cipherDataNode, xmlSecEncStatePtr state, 
			 xmlSecEncResultPtr result) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(cipherDataNode != NULL, -1);
    xmlSecAssert2(state!= NULL, -1);    
    xmlSecAssert2(result != NULL, -1);
    
    cur = xmlSecGetNextElementNode(cipherDataNode->children);

    /* CipherValue or CipherReference */
    if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeCipherValue, xmlSecEncNs))) {
	ret = xmlSecCipherValueNodeRead(cur, state, result);
	if(ret < 0){
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecCipherValueNodeRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	cur = xmlSecGetNextElementNode(cur->next);	
    } else if((cur != NULL) && (xmlSecCheckNodeName(cur, xmlSecNodeCipherReference,  xmlSecEncNs))) { 
	ret = xmlSecCipherReferenceNodeRead(cur, state, result);
	if(ret < 0){
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecCipherReferenceNodeRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    return(-1);
	}
	cur = xmlSecGetNextElementNode(cur->next);	
    }

    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}


/**
 * xmlSecCipherDataNodeWrite:
 */
static int
xmlSecCipherDataNodeWrite(xmlNodePtr cipherDataNode,
		      const unsigned char *buf, size_t size) {
    xmlNodePtr cur; 

    xmlSecAssert2(cipherDataNode != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);    

    cur = xmlSecGetNextElementNode(cipherDataNode->children);
    if(cur == NULL) {
	cur = xmlSecAddChild(cipherDataNode, xmlSecNodeCipherValue, xmlSecEncNs);
	if(cur == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecAddChild",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"node=%s",
			xmlSecErrorsSafeString(xmlSecNodeCipherValue));
	    return(-1);	    	    
	}
        xmlNodeSetContent(cur, BAD_CAST "\n");
	xmlNodeAddContentLen(cur, buf, size);
        xmlNodeAddContent(cur, BAD_CAST "\n");
	return(0);
    } else if(xmlSecCheckNodeName(cur, BAD_CAST "CipherValue", xmlSecEncNs)) {
        xmlNodeSetContent(cur, BAD_CAST "\n");
	xmlNodeAddContentLen(cur, buf, size);
        xmlNodeAddContent(cur, BAD_CAST "\n");
	cur = xmlSecGetNextElementNode(cur->next);
    } else if(xmlSecCheckNodeName(cur, BAD_CAST "CipherReference", xmlSecEncNs)) {
	/* do nothing! */
	cur = xmlSecGetNextElementNode(cur->next);
    }
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    return(0);
}

/**
 * xmlSecCipherValueNodeRead:
 */
static int
xmlSecCipherValueNodeRead(xmlNodePtr cipherValueNode, xmlSecEncStatePtr state, 
			  xmlSecEncResultPtr result) {
    xmlSecTransformCtx transformCtx;
    xmlSecTransformPtr base64;
    xmlSecTransformPtr memBuf;
    xmlChar *content;
    int ret;

    xmlSecAssert2(cipherValueNode != NULL, -1);
    xmlSecAssert2(state!= NULL, -1);    
    xmlSecAssert2(result != NULL, -1);
    
    /* first transform for decryption is base64 decode */	
    base64 = xmlSecTransformCreate(xmlSecTransformBase64Id, 0);
    if(base64 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecTransformBase64Id)));
	return(-1);
    }

    ret = xmlSecEncStateAddFirstTransform(state, base64);
    if(ret < 0) {    
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncStateAddFirstTransform",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformGetName(base64)));
	return(-1);
    }


    /* add mem buf at the end */
    memBuf = xmlSecTransformCreate(xmlSecTransformMemBufId, 0);
    if(memBuf == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformKlassGetName(xmlSecTransformMemBufId)));
	return(-1);
    }
    ret = xmlSecEncStateAddTransform(state, memBuf);
    if(ret < 0) {    
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecEncStateAddTransform",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformGetName(memBuf)));
	xmlSecTransformDestroy(memBuf, 1); 
	return(-1);
    }


    /* get node content */
    content = xmlNodeGetContent(cipherValueNode);
    if(content == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlNodeGetContent",
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "node=%s",
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cipherValueNode)));
	return(-1);
    }
	
    /* decrypt the data */
    ret = xmlSecTransformPushBin(state->first, content, xmlStrlen(content), 1, &transformCtx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformPushBin",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformGetName(state->first)));
	xmlFree(content);
	return(-1);	    	
    }
	
    result->buffer = xmlSecTransformMemBufGetBuffer((xmlSecTransformPtr)state->last, 1);
    if(result->buffer == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformMemBufGetBuffer",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "transform=%s",
		    xmlSecErrorsSafeString(xmlSecTransformGetName(state->last)));
	xmlFree(content);
        return(-1);	    	
    }
    
    xmlFree(content);
    return(0);
}

static int			
xmlSecCipherReferenceNodeRead(xmlNodePtr cipherReferenceNode, xmlSecEncStatePtr state, 
			      xmlSecEncResultPtr result) {
    xmlSecTransformPtr transform;
    xmlSecTransformStatePtr transState = NULL;
    xmlNodePtr cur;
    xmlChar *uri = NULL;
    int res = -1;
    int ret;

    xmlSecAssert2(cipherReferenceNode != NULL, -1);
    xmlSecAssert2(state!= NULL, -1);    
    xmlSecAssert2(result != NULL, -1);
    
    cur = xmlSecGetNextElementNode(cipherReferenceNode->children);     
    uri = xmlGetProp(cipherReferenceNode, xmlSecAttrURI);
    transState = xmlSecTransformStateCreate(cipherReferenceNode->doc, NULL, (char*)uri);
    if(transState == NULL){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformStateCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }	
    
    /* first is optional Transforms node */
    if((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeTransforms, xmlSecEncNs)) {
	ret = xmlSecTransformsNodeRead(transState, cur);
	if(ret < 0){
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformsNodeRead",
		        XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    goto done;
	}	
	cur = xmlSecGetNextElementNode(cur->next);
    }
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    xmlSecErrorsSafeString(xmlSecNodeGetName(cur)),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    /* copy all transforms from encryption state to transform state */
    while(state->first != NULL) {
	transform = state->first;
	state->first = state->first->next;
	transform->next = NULL;
	if(state->first != NULL) {
	    state->first->prev = NULL;
	}
	
	ret = xmlSecTransformStateUpdate(transState, transform);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecTransformStateUpdate",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"transform=%s",
			xmlSecErrorsSafeString(xmlSecTransformGetName(transform)));
	    xmlSecTransformDestroyAll((xmlSecTransformPtr)transform);
	    goto done;
	}
    }
    state->last = NULL;
    ret = xmlSecTransformStateFinal(transState, xmlSecTransformResultBinary);
    if((ret < 0) || (transState->curBuf == NULL)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    NULL,
		    "xmlSecTransformStateFinal",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformResultBinary");
	goto done;
    }
    result->buffer = transState->curBuf;
    transState->curBuf = NULL;
    
    res = 0;
done:
    if(uri != NULL) {
	xmlFree(uri);
    }
    if(transState != NULL) {
	xmlSecTransformStateDestroy(transState);
    }
    return(res);
}


