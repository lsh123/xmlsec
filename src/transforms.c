/** 
 * XML Security Library
 *
 * The Transforms Element (http://www.w3.org/TR/xmldsig-core/#sec-Transforms)
 * 
 * The optional Transforms element contains an ordered list of Transform 
 * elements; these describe how the signer obtained the data object that 
 * was digested.
 *
 * Schema Definition:
 * 
 *  <element name="Transforms" type="ds:TransformsType"/>
 *  <complexType name="TransformsType">
 *    <sequence>
 *      <element ref="ds:Transform" maxOccurs="unbounded"/> 
 *    </sequence>
 *   </complexType>
 *
 *  <element name="Transform" type="ds:TransformType"/>
 *  <complexType name="TransformType" mixed="true">
 *    <choice minOccurs="0" maxOccurs="unbounded"> 
 *      <any namespace="##other" processContents="lax"/>
 *      <!-- (1,1) elements from (0,unbounded) namespaces -->
 *      <element name="XPath" type="string"/> 
 *    </choice>
 *    <attribute name="Algorithm" type="anyURI" use="required"/> 
 *  </complexType>
 *    
 * DTD:
 *    
 *  <!ELEMENT Transforms (Transform+)>
 *  <!ELEMENT Transform (#PCDATA|XPath %Transform.ANY;)* >
 *  <!ATTLIST Transform Algorithm    CDATA    #REQUIRED >
 *  <!ELEMENT XPath (#PCDATA) >
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */

#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpointer.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/io.h>
#include <xmlsec/membuf.h>
#include <xmlsec/errors.h>

#define XMLSEC_TRANSFORM_BUFFER_SIZE    1024


static xmlSecTransformId xmlSecAllTransforms[100];

/* internal functions */
static int  xmlSecTransformStateParseUri(xmlSecTransformStatePtr state, const char *uri);
static void xmlSecTransformStateDestroyCurrentDoc(xmlSecTransformStatePtr state);
static int  xmlSecTransformCreateXml(xmlSecTransformStatePtr state);
static int  xmlSecTransformCreateBin(xmlSecTransformStatePtr state);
static int  xmlSecTransformCreateBinFromXml(xmlSecTransformStatePtr state);
static int  xmlSecTransformCreateBinFromUri(xmlSecTransformStatePtr state);
static int xmlSecTransformPreBase64Decode(const xmlNodePtr node, xmlSecNodeSetPtr nodeSet, 
					  xmlOutputBufferPtr output);

/**********************************************************************
 *
 * Hi-level functions
 *
 *********************************************************************/
/**
 * xmlSecTransformsInit:
 *
 * Trnasforms engine initialization (called from xmlSecInit() function).
 * The applications should not call this function directly.
 */
void xmlSecTransformsInit(void) {
    int i = 0;

    /* encoding */
    xmlSecAllTransforms[i++] = xmlSecEncBase64Encode;
    xmlSecAllTransforms[i++] = xmlSecEncBase64Decode;
    
    /* digest methods */
#ifndef XMLSEC_NO_SHA1    
    xmlSecAllTransforms[i++] = xmlSecDigestSha1;
#endif /* XMLSEC_NO_SHA1 */
#ifndef XMLSEC_NO_RIPEMD160
    xmlSecAllTransforms[i++] = xmlSecDigestRipemd160;
#endif /* XMLSEC_NO_RIPEMD160 */

    /* MAC */ 
#ifndef XMLSEC_NO_HMAC
    xmlSecAllTransforms[i++] = xmlSecMacHmacSha1;
    xmlSecAllTransforms[i++] = xmlSecMacHmacRipeMd160;
    xmlSecAllTransforms[i++] = xmlSecMacHmacMd5;
#endif /* XMLSEC_NO_HMAC */

    /* signature */ 
#ifndef XMLSEC_NO_DSA
    xmlSecAllTransforms[i++] = xmlSecSignDsaSha1;
#endif /* XMLSEC_NO_DSA */    

#ifndef XMLSEC_NO_RSA
    xmlSecAllTransforms[i++] = xmlSecSignRsaSha1;
#endif /* XMLSEC_NO_RSA */
    
    /* c14n methods */
    xmlSecAllTransforms[i++] = xmlSecC14NInclusive;
    xmlSecAllTransforms[i++] = xmlSecC14NInclusiveWithComments;
    xmlSecAllTransforms[i++] = xmlSecC14NExclusive;
    xmlSecAllTransforms[i++] = xmlSecC14NExclusiveWithComments;

    /* XML transforms */
    xmlSecAllTransforms[i++] = xmlSecTransformEnveloped;
    xmlSecAllTransforms[i++] = xmlSecTransformXPath;
    xmlSecAllTransforms[i++] = xmlSecTransformXPath2;
    xmlSecAllTransforms[i++] = xmlSecTransformXPointer;

#ifndef XMLSEC_NO_XSLT
    xmlSecAllTransforms[i++] = xmlSecTransformXslt;
#endif /* XMLSEC_NO_XSLT */    

    /* encryption */
#ifndef XMLSEC_NO_DES    
    xmlSecAllTransforms[i++] = xmlSecEncDes3Cbc;
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES    
    xmlSecAllTransforms[i++] = xmlSecEncAes128Cbc;
    xmlSecAllTransforms[i++] = xmlSecEncAes192Cbc;
    xmlSecAllTransforms[i++] = xmlSecEncAes256Cbc;
#endif /* XMLSEC_NO_AES */

    /* Key Transports */
#ifndef XMLSEC_NO_RSA
    xmlSecAllTransforms[i++] = xmlSecEncRsaPkcs1;
    xmlSecAllTransforms[i++] = xmlSecEncRsaOaep;
#endif /* XMLSEC_NO_RSA */

    /* key wrappers */
#ifndef XMLSEC_NO_AES    
    xmlSecAllTransforms[i++] = xmlSecKWDes3Cbc;
    xmlSecAllTransforms[i++] = xmlSecKWAes128;
    xmlSecAllTransforms[i++] = xmlSecKWAes192;
    xmlSecAllTransforms[i++] = xmlSecKWAes256;
#endif /* XMLSEC_NO_DES */

    /* Input/memory buffer */
    xmlSecAllTransforms[i++] = xmlSecInputUri;
    xmlSecAllTransforms[i++] = xmlSecMemBuf;

    /* MUST be the last in the list */
    xmlSecAllTransforms[i++] = xmlSecTransformUnknown;
}

/**
 * xmlSecTransformsNodeRead:
 * @state: the pointer to current transform state.
 * @transformsNode: the pointer to the <dsig:Transform> node.
 *
 * Reads the transform node and updates @state,
 *
 * Returns 0 on success or a negative value otherwise.
 */ 
int
xmlSecTransformsNodeRead(xmlSecTransformStatePtr state, 
			 xmlNodePtr transformsNode) {
    xmlNodePtr cur;
    xmlSecTransformPtr transform;
    int ret;    

    xmlSecAssert2(state != NULL, -1);        
    xmlSecAssert2(transformsNode != NULL, -1);
    
    cur = xmlSecGetNextElementNode(transformsNode->children);
    while((cur != NULL) && xmlSecCheckNodeName(cur, BAD_CAST "Transform", xmlSecDSigNs)) {
	transform = xmlSecTransformNodeRead(cur, xmlSecUsageDSigTransform, 0);
	if(transform == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformNodeRead");
	    return(-1);
	}
	ret = xmlSecTransformStateUpdate(state, transform);
	if(ret < 0){
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformStateUpdate");
	    xmlSecTransformDestroy(transform, 1);
	    return(-1);
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    (cur->name != NULL) ? (char*)cur->name : "NULL");
	return(-1);
    }    
    return(0);
}

/** 
 * xmlSecTransformNodeRead:
 * @transformNode: the pointer to <dsig:Transform> node.
 * @usage: the usage of the transfomr (signature, encryption, etc.).
 * @dontDestroy: the flag whether we need to destroy the transform.
 *
 * Reads transform from the @transformNode as follows:
 *    1) reads "Algorithm" attribute;
 *    2) checks the list of known algorithms;
 *    3) calls transform create method;
 *    4) calls transform read transform node method.
 *
 * Returns the pointer to newly allocated #xmlSecTransform structure
 * or NULL if an error occurs.
 */
xmlSecTransformPtr	
xmlSecTransformNodeRead(xmlNodePtr transformNode, xmlSecTransformUsage usage,
			int dontDestroy) {
    xmlChar *href;
    xmlSecTransformId id;
    xmlSecTransformPtr transform;
    int ret;
    
    xmlSecAssert2(transformNode != NULL, NULL);
    
    href = xmlGetProp(transformNode, BAD_CAST "Algorithm");
    if(href == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_NODE_ATTRIBUTE,
		    "Algorithm");
	return(NULL);		
    }
    
    id = xmlSecTransformFind(href);    
    if(id == xmlSecTransformUnknown) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformFind(href=\"%s\")", href);
	xmlFree(href);
	return(NULL);		
    }
    
    transform = xmlSecTransformCreate(id, usage, dontDestroy);
    if(!xmlSecTransformIsValid(transform)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformCreate(href=\"%s\")", href);
	xmlFree(href);
	return(NULL);		
    }
    
    ret = xmlSecTransformRead(transform, transformNode);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformRead - %d", ret);
	xmlSecTransformDestroy(transform, 1);
	xmlFree(href);
	return(NULL);		
    }
    
    xmlFree(href);   
    return(transform);
}

/**
 * xmlSecTransformNodeWrite:
 * @transformNode: the pointer to <dsig:Transform> node.
 * @id: the transform id.
 *
 * Writes Agorithm attribute in the transform node.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecTransformNodeWrite(xmlNodePtr transformNode, xmlSecTransformId id) {
    xmlSecAssert2(transformNode != NULL, -1);
    xmlSecAssert2(id != NULL, -1);
    
    if(xmlSetProp(transformNode, BAD_CAST "Algorithm", id->href) == NULL) {	
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlSetProp(Algorithm)");
	return(-1);	
    }

    return(0);
}

/**************************************************************************
 *
 * Transform Info
 *
 **************************************************************************/ 
/**
 * xmlSecTransformFind:
 * @href: the transform href.
 *
 * Searches the list of known transforms for transform with given href
 *
 * Returns the id of the found transform or NULL if an error occurs 
 * or transform is not found.
 */ 
xmlSecTransformId
xmlSecTransformFind(const xmlChar* href) {
    xmlSecTransformId *ptr;

    xmlSecAssert2(href != NULL, NULL);
    
    ptr = xmlSecAllTransforms;
    while((*ptr) != xmlSecTransformUnknown) {
	if(xmlStrEqual((*ptr)->href, href)) {
	    return(*ptr);
	}
	++ptr;
    }
    
    /* not found */
    xmlSecError(XMLSEC_ERRORS_HERE,
		XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		"href=%s", href);    
    return(xmlSecTransformUnknown);
}

/**********************************************************************
 *
 * Transform 
 *
 *********************************************************************/ 
/**
 * xmlSecTransformCreate:
 * @id: the transform id to create.
 * @usage: the proposed transform usage.
 * @dontDestroy: the flag that controls wherther the transforms
 *		can destroy the transforms automatically
 *
 * Creates new transform from the transform id object.
 *
 * Returns the pointer to newly created #xmlSecTransform structure
 * or NULL if an error occurs.
 */ 
xmlSecTransformPtr	
xmlSecTransformCreate(xmlSecTransformId id, xmlSecTransformUsage usage, 
		      int dontDestroy) {
    xmlSecTransformPtr transform;
    
    xmlSecAssert2(id != NULL, NULL);
    xmlSecAssert2(id->create != NULL, NULL);

    if((id->usage & usage) != usage) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_USAGE,
		    "transform usage=0x%08x, requested usage %0x08x", 
		    (unsigned)id->usage, (unsigned)usage);
	return(NULL);		
    }

        
    transform = id->create(id);
    if(transform == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "id->create");
	return(NULL);	
    }
    transform->dontDestroy = dontDestroy;
    return(transform);
}

/**
 * xmlSecTransformDestroy:
 * @transform: the pointer to #xmlSecTransform structure.
 * @forceDestroy: the flag whether the transform destruction will be
 *   forced.
 *
 * Destroys transform by calling appropriate transform specific function.
 */
void
xmlSecTransformDestroy(xmlSecTransformPtr transform, int forceDestroy) {
    xmlSecAssert(transform != NULL);
    xmlSecAssert(transform->id != NULL);
    xmlSecAssert(transform->id->destroy != NULL);
    
    if(!xmlSecTransformIsValid(transform)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    " ");
	return;
    }
    
    /*
     * Special case for binary transforms: need to remove from chain 
     */
    if(transform->id->type == xmlSecTransformTypeBinary) {
	xmlSecBinTransformRemove(transform);
    }

    if((transform->dontDestroy) && (!forceDestroy)){
	/* requested do not destroy transform */
	return;
    }    
    transform->id->destroy(transform);
}

/** 
 * xmlSecTransformRead:
 * @transform: the pointer to #xmlSecTransform structure.
 * @transformNode: the pointer to the <dsig:Transform> node.
 *
 * Reads transform information from the @transformNode using 
 * transform specific function.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecTransformRead(xmlSecTransformPtr transform, xmlNodePtr transformNode) {

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(transformNode != NULL, -1);

    if(!xmlSecTransformIsValid(transform)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    " ");
	return(-1);
    }
    if(transform->id->read != NULL) {
	return(transform->id->read(transform, transformNode));
    }
    return(0);
}

/**********************************************************************
 *
 * Binary transform
 *
 *********************************************************************/ 
/**
 * xmlSecBinTransformAddKey:
 * @transform: the pointer to #xmlSecTransform structure.
 * @key: the pointer to #xmlSecKey structure. 
 *
 * Sets the key for binary transform (wrapper for transform specific 
 * addBinKey() method).
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecBinTransformAddKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    xmlSecBinTransformId id;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
        
    if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeBinary)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformTypeBinary");
	return(-1);
    }

    id = ((xmlSecBinTransformId)(transform->id));
    if(id->addBinKey != NULL) {
	return((id->addBinKey)((xmlSecBinTransformPtr)transform, key));
    }
    return(0);
}

/**
 * xmlSecBinTransformRead:
 * @transform: the pointer to #xmlSecTransform structure.
 * @buf: the output buffer.
 * @size: the output buffer size.
 *
 * Reads chunk of data from the transform (wrapper transform specific
 * readBin() function).
 *
 * Returns the number of bytes in the buffer or negative value
 * if an error occurs.
 */
int
xmlSecBinTransformRead(xmlSecTransformPtr transform, 
		       unsigned char *buf, size_t size) {
    xmlSecBinTransformId id;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    
    if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeBinary)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformTypeBinary");
	return(-1);
    }
    
    id = ((xmlSecBinTransformId)(transform->id));
    if(id->readBin != NULL) {
	return((id->readBin)((xmlSecBinTransformPtr)transform, buf, size));
    }
    return(0);
}

/**
 * xmlSecBinTransformWrite:
 * @transform: the pointer to #xmlSecTransform structure.
 * @buf: the input data buffer.
 * @size: the input data size.
 *
 * Writes data to the transform (wrapper to the transform specific
 * writeBin() function).
 * 
 * Returns 0 if success or a negative value otherwise.
 */
int
xmlSecBinTransformWrite(xmlSecTransformPtr transform, 
			const unsigned char *buf, size_t size) {
    xmlSecBinTransformId id;

    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    
    if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeBinary)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformTypeBinary");
	return(-1);
    }
    
    id = ((xmlSecBinTransformId)(transform->id));
    if(id->writeBin != NULL) {
	return((id->writeBin)((xmlSecBinTransformPtr)transform, buf, size));
    }
    return(0);
}

/**
 * xmlSecBinTransformFlush:
 * @transform: the pointer to #xmlSecTransform structure.
 *
 * Finalizes writing (wrapper for transform specific flushBin() method). 
 *
 * Returns 0 if success or negative value otherwise.
 */
int
xmlSecBinTransformFlush(xmlSecTransformPtr transform) {
    xmlSecBinTransformId id;
    
    xmlSecAssert2(transform != NULL, -1);

    if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeBinary)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformTypeBinary");
	return(-1);
    }
    
    id = ((xmlSecBinTransformId)(transform->id));
    if(id->flushBin != NULL) {
	return((id->flushBin)((xmlSecBinTransformPtr)transform));
    }
    return(0);
}

/**
 * xmlSecBinTransformAddAfter:
 * @curTransform: the pointer to current transform (may be NULL).
 * @newTransform: the pointer to new transform.
 * 
 * Adds @newTransform after the @curTransform.
 *
 * Returns pointer to the new transforms chain or NULL if an error occurs.
 */
xmlSecTransformPtr	
xmlSecBinTransformAddAfter(xmlSecTransformPtr curTransform, 
			xmlSecTransformPtr newTransform) {
    xmlSecBinTransformPtr c;
    xmlSecBinTransformPtr n;

    xmlSecAssert2(newTransform != NULL, NULL);
    
    if(((curTransform != NULL) && !xmlSecTransformCheckType(curTransform, xmlSecTransformTypeBinary)) ||
       !xmlSecTransformCheckType(newTransform, xmlSecTransformTypeBinary)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformTypeBinary");
	return(NULL);
    }

    c = (xmlSecBinTransformPtr)curTransform;
    n = (xmlSecBinTransformPtr)newTransform;
    if(c != NULL) {
	n->prev = c;
	n->next = c->next;
	c->next = n;
	if(n->next != NULL) {
	    n->next->prev = n;
	}
    } else {
 	n->next = n->prev = NULL;
    }
    return(newTransform);
}

/**
 * xmlSecBinTransformAddBefore
 * @curTransform: the pointer to current transform (may be NULL).
 * @newTransform: the pointer to new transform.
 * 
 * Adds @newTransform before the @curTransform.
 *
 * Returns pointer to the new transforms chain or NULL if an error occurs.
 */
xmlSecTransformPtr	
xmlSecBinTransformAddBefore(xmlSecTransformPtr curTransform, 
			    xmlSecTransformPtr newTransform) {
    xmlSecBinTransformPtr c;
    xmlSecBinTransformPtr n;

    xmlSecAssert2(newTransform != NULL, NULL);

    if(((curTransform != NULL) && !xmlSecTransformCheckType(curTransform, xmlSecTransformTypeBinary)) ||
       !xmlSecTransformCheckType(newTransform, xmlSecTransformTypeBinary)) {

	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformTypeBinary");
	return(NULL);
    }

    c = (xmlSecBinTransformPtr)curTransform;
    n = (xmlSecBinTransformPtr)newTransform;
    if(c != NULL) {
	n->next = c;
	n->prev = c->prev;
	c->prev = n;
	if(n->prev != NULL) {
	    n->prev->next = n;
	}
    } else {
	n->next = n->prev = NULL;
    }
    return(newTransform);
    
}

/**
 * xmlSecBinTransformRemove:
 * @transform: the pointer to #xmlSecTransform structure.
 *
 * Removes @transform from the chain. This method MUST be called by any 
 * bin transform id destructor.
 */
void
xmlSecBinTransformRemove(xmlSecTransformPtr transform) {
    xmlSecBinTransformPtr t;
    
    xmlSecAssert(transform != NULL);
    
    if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeBinary)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformTypeBinary");
	return;
    }

    t = (xmlSecBinTransformPtr)transform;
    if(t->next != NULL) {
	t->next->prev = t->prev;
    }
    if(t->prev != NULL) {
	t->prev->next = t->next;
    }
    t->next = t->prev = NULL;
}

/**
 * xmlSecBinTransformDestroyAll:
 * @transform: the pointer to #xmlSecTransform structure.
 *
 * Destroys all transforms in the chain.
 */
void
xmlSecBinTransformDestroyAll(xmlSecTransformPtr transform) {
    xmlSecBinTransformPtr t;

    xmlSecAssert(transform != NULL);

    if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeBinary)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformTypeBinary");
	return;
    }
    
    t = (xmlSecBinTransformPtr)transform;
    while(t->next != NULL) {
	xmlSecTransformDestroy((xmlSecTransformPtr)(t->next), 0);
    }
    while(t->prev != NULL) {
	xmlSecTransformDestroy((xmlSecTransformPtr)(t->prev), 0);
    }	
    xmlSecTransformDestroy((xmlSecTransformPtr)t, 0);
}

/**
 * xmlSecBinTransformSetEncrypt:
 * @transform: the pointer to #xmlSecTransform structure.
 * @encrypt: the encrypt/decrypt (or encode/decode) flag.
 *
 * Sets the @transform direction - encrypt/decrypt (or encode/decode).
 */
void	
xmlSecBinTransformSetEncrypt(xmlSecTransformPtr transform, int encrypt) {
    xmlSecBinTransformPtr t;

    xmlSecAssert(transform != NULL);

    if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeBinary)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformTypeBinary");
	return;
    }
    
    t = (xmlSecBinTransformPtr)transform;
    t->encode = encrypt;
}

    
/**************************************************************************
 *
 * XML Transform
 *
 *************************************************************************/
/**
 * xmlSecXmlTransformExecute:
 * @transform: the pointer to XML transform.
 * @ctxDoc: the pointer to the document containing the transform's 
 *		<dsig:Transform> node.
 * @doc: the pointer to the pointer to current document.
 * @nodes: the pointer to the pointer to current and result nodes set.
 *
 * Executes the XML @transform and returns result nodes set in @nodes
 * (wrapper for transform specific executeXml() method).
 *
 * Returns 0 on success or a negative value otherwise.
 */
int
xmlSecXmlTransformExecute(xmlSecTransformPtr transform, xmlDocPtr ctxDoc,
			  xmlDocPtr *doc, xmlSecNodeSetPtr *nodes) {
    xmlSecXmlTransformId id;
    
    xmlSecAssert2(transform != NULL, -1);
    xmlSecAssert2(doc != NULL, -1);
    xmlSecAssert2((*doc) != NULL, -1);

    if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeXml)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecTransformTypeXml");
	return(-1);
    }
    
    id = ((xmlSecXmlTransformId)(transform->id));
    if(id->executeXml != NULL) {
	return((id->executeXml)((xmlSecXmlTransformPtr)transform, ctxDoc, 
				 doc, nodes));
    }
    return(0);
}

/*************************************************************************
 *
 * C14N Transform
 *
 ************************************************************************/ 
/**
 * xmlSecC14NTransformExecute:
 * @transform: the pointer to C14N transform.
 * @doc: the pointer to current document.
 * @nodes: the pointer to current nodes set.
 * @buffer: the result buffer.
 *
 * Executes the C14N @transform and returns result in the @buffer
 * (wrapper for transform specific executeC14n() method). If the 
 * @trnaform is NULL then the default #xmlSecC14NInclusive 
 * transform is executed.
 *
 * Returns 0 on success or a negative value otherwise.
 */
int	
xmlSecC14NTransformExecute(xmlSecTransformPtr transform,
			   xmlDocPtr doc, xmlSecNodeSetPtr nodes,
			   xmlOutputBufferPtr buffer) {
    xmlSecC14NTransformId id;  

    xmlSecAssert2(doc != NULL, -1);
    xmlSecAssert2(buffer != NULL, -1);
    
    if(transform != NULL) {
	if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeC14N)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_INVALID_TRANSFORM,
			"xmlSecTransformTypeC14N");
	    return(-1);
	}
	id = ((xmlSecC14NTransformId)(transform->id));
    } else {
	id = (xmlSecC14NTransformId)xmlSecC14NInclusive; /* the default c14n transform */
    }
    
    if(id->executeC14N != NULL) {
	return((id->executeC14N)((xmlSecC14NTransformPtr)transform, 
				  doc, nodes, buffer));
    }
    return(0);
}


/***************************************************************************
 *
 * Transforms State
 *
 **************************************************************************/
/**
 * xmlSecTransformStateCreate:
 * @doc: the pointer to XML document that contains <dsig:Signature> node.
 * @nodeSet: the original nodes set.
 * @uri: the original uri.
 *
 * Creates new transform state.
 *
 * Returns pointer to newly allocated #xmlSecTransformState structure
 * or NULL if an error occurs.
 */
xmlSecTransformStatePtr	
xmlSecTransformStateCreate(xmlDocPtr doc, xmlSecNodeSetPtr nodeSet, 
			   const char *uri) {
    xmlSecTransformStatePtr state;
    int ret;

    /*
     * Allocate a new xmlSecTransformState and fill the fields.
     */
    state = (xmlSecTransformStatePtr) xmlMalloc(sizeof(xmlSecTransformState));
    if(state == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecTransformState)=%d",
		    sizeof(xmlSecTransformState));
	return(NULL);
    }
    memset(state, 0, sizeof(xmlSecTransformState));
    
    state->curBuf = xmlBufferCreate();
    if(state->curBuf == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlBufferCreate");
	xmlSecTransformStateDestroy(state);
        return(NULL);
    }

    state->initDoc = doc;
    state->initNodeSet = nodeSet;
    ret = xmlSecTransformStateParseUri(state, uri);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformStateParseUri(%s)", (uri != NULL) ? uri : "NULL");
	xmlSecTransformStateDestroy(state);
    	return(NULL);
    }
        
    return(state);     
}

/**
 * xmlSecTransformStateDestroy:
 * @state: the pointer to #xmlSecTransformState structure.
 *
 * Destroys the transform state.
 */
void
xmlSecTransformStateDestroy(xmlSecTransformStatePtr state) {
    xmlSecAssert(state != NULL);

    xmlSecTransformStateDestroyCurrentDoc(state);
    if(state->curBuf != NULL) {
	xmlBufferEmpty(state->curBuf);
	xmlBufferFree(state->curBuf);
    }
    if(state->curFirstBinTransform != NULL) {
	xmlSecBinTransformDestroyAll(state->curFirstBinTransform);
    } else if(state->curLastBinTransform != NULL) {
	xmlSecBinTransformDestroyAll(state->curLastBinTransform); 
    }
    if(state->initUri != NULL) {
	xmlFree(state->initUri);
    }
    memset(state, 0, sizeof(xmlSecTransformState));
    xmlFree(state);    
}

/**
 * xmlSecTransformStateUpdate:
 * @state: the pointer to #xmlSecTransformState structure.
 * @transform: the pointer to #xmlSecTransform structure.
 *
 * Updates the current @state with @transform. Note all transforms are
 * applied immidiatelly.
 *
 * Returns 0 on success or negative value otherwise.
 */
int
xmlSecTransformStateUpdate(xmlSecTransformStatePtr state, 
			   xmlSecTransformPtr transform) {
    int ret;

    xmlSecAssert2(state != NULL, -1);
    xmlSecAssert2(transform != NULL, -1);
    
    if(!xmlSecTransformIsValid(transform)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    " ");
	return(-1);
    }
    
    switch(transform->id->type) {
    case xmlSecTransformTypeBinary:     	
	    /* simply add transform to the chain */
	transform = xmlSecBinTransformAddAfter(state->curFirstBinTransform, 
					     transform);
	if(transform == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBinTransformAddAfter");
	    return(-1);
	}
	if(state->curFirstBinTransform == NULL) {
	    state->curFirstBinTransform = transform;
	}
	state->curLastBinTransform = transform;
	break;
    case xmlSecTransformTypeXml: {
	xmlDocPtr doc;
	xmlSecNodeSetPtr nodes;
	
        ret = xmlSecTransformCreateXml(state);
        if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformCreateXml - %d", ret);
	    return(-1);
	}
	
	doc = state->curDoc;
	nodes = state->curNodeSet;
	
	ret = xmlSecXmlTransformExecute(transform, state->initDoc, &doc, &nodes);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecXmlTransformExecute - %d", ret);
	    return(-1);
	}
	xmlSecTransformDestroy(transform, 0);
	if(doc != state->curDoc) {
	    xmlSecTransformStateDestroyCurrentDoc(state);
	} else if(nodes != state->curNodeSet) {
	    if((state->curNodeSet != NULL) && (state->curNodeSet != state->initNodeSet)) {
    		xmlSecNodeSetDestroy(state->curNodeSet);
	    }
	}	
	state->curDoc = doc;
	state->curNodeSet = nodes;
    	break;
	}
    case xmlSecTransformTypeC14N:
	ret = xmlSecTransformCreateXml(state);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformCreateXml - %d", ret);
	    return(-1);
	}
	state->curC14NTransform = transform;
	break;
    default:
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "transform type %d", transform->id->type);
	return(-1);	    
    }
    return(0);
}

/**
 * xmlSecTransformStateFinal:
 * @state: the pointer to #xmlSecTransformState structure.
 * @type: the desired final type.
 *
 * Finalazies transforms @state (applies all pending transforms) and 
 * creates a result of the desired @type.
 *
 * Returns 0 on success or negative value otherwise.
 */
int
xmlSecTransformStateFinal(xmlSecTransformStatePtr state, 
			  xmlSecTransformResult type) {
    int ret;

    xmlSecAssert2(state != NULL, -1);
    
    switch(type) {
    case xmlSecTransformResultBinary:
	ret = xmlSecTransformCreateBin(state);
	break;
    case xmlSecTransformResultXml:
	ret = xmlSecTransformCreateXml(state);
	break;
    default:
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_TYPE,
		    "result type %d", type);
	return(-1);	
    }    

    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformCreateBin or xmlSecTransformCreateXml - %d", ret);
	return(-1);	
    }
    return(0);
}

/**
 * xmlSecTransformStateParseUri:
 *
 * Parses uri and loads the document if required:
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-ReferenceProcessingModel:
 *
 * The following examples demonstrate what the URI attribute identifies and
 * how it is dereferenced:
 *
 * - URI="http://example.com/bar.xml"
 * Identifies the octets that represent the external resource 
 * 'http://example.com/bar.xml', that is probably an XML document given 
 * its file extension. 
 * - URI="http://example.com/bar.xml#chapter1"
 * Identifies the element with ID attribute value 'chapter1' of the 
 * external XML resource 'http://example.com/bar.xml', provided as an 
 * octet stream. Again, for the sake of interoperability, the element 
 * identified as 'chapter1' should be obtained using an XPath transform 
 * rather than a URI fragment (barename XPointer resolution in external 
 * resources is not REQUIRED in this specification). 
 * - URI=""
 * Identifies the node-set (minus any comment nodes) of the XML resource 
 * containing the signature 
 * - URI="#chapter1"
 * Identifies a node-set containing the element with ID attribute value 
 * 'chapter1' of the XML resource containing the signature. XML Signature 
 * (and its applications) modify this node-set to include the element plus 
 * all descendents including namespaces and attributes -- but not comments.
 *
 */
static int 
xmlSecTransformStateParseUri(xmlSecTransformStatePtr state, const char *uri) {
    const char* xptr;

    xmlSecAssert2(state != NULL, -1);
    
    if(uri == NULL) {
	state->curDoc 	  = state->initDoc;
	state->curNodeSet = state->initNodeSet;
    } else if(strcmp(uri, "") == 0) {
	/* all nodes set but comments */
	state->curDoc 	  = state->initDoc;
	state->curNodeSet = xmlSecNodeSetGetChildren(state->initDoc, 
				xmlDocGetRootElement(state->initDoc), 
				0, 0);
	if(state->curNodeSet == NULL){
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecNodeSetGetChildren");
	    return(-1);
	}
    } else if((xptr = strchr(uri, '#')) == NULL) {
        state->initUri = (char*)xmlStrdup(BAD_CAST uri);
	if(state->initUri == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_MALLOC_FAILED,
			"xmlStrdup");
	    return(-1);
	}
	/* simple URI -- do not load document for now */
    } else {
    	state->initUri = (char*)xmlStrndup(BAD_CAST uri, xptr - uri);
	if(state->initUri == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_MALLOC_FAILED,
			"xmlStrndup");
	    return(-1);
	}
	
        /* if the uri is not empty, need to load document */
	if(strlen(state->initUri) > 0) {
	    state->curDoc = xmlSecParseFile(state->initUri); 
	    if(state->curDoc == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecParseFile(%s)", state->initUri);
		return(-1);	    
	    }
	} else {
	    state->curDoc = state->initDoc; 
	}

	/* 
	 * now evaluate xptr if it is present and does not 
	 * equal to everything
	 */
	if((xptr != NULL) && (strcmp(xptr, "#xpointer(/)") != 0)) {   
            xmlXPathContextPtr ctxt;
	    xmlXPathObjectPtr res;
	    xmlSecNodeSetType type;

	    ctxt = xmlXPtrNewContext(state->curDoc, 
				    xmlDocGetRootElement(state->curDoc), 
				    NULL);
	    if(ctxt == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XML_FAILED,
			    "xmlXPtrNewContext");
		return(-1);	    
	    }
	    
	    /* evaluate expression but skip '#' */
	    if(strncmp(xptr, "#xpointer(", 10) == 0) {
		type = xmlSecNodeSetTree;
		res = xmlXPtrEval(BAD_CAST (xptr + 1), ctxt);
	    } else {
		static xmlChar tmpl[] = "xpointer(id(\'%s\'))";
		xmlChar* tmp;
		int size;
		
		/* we need to construct new expression */
		size = xmlStrlen(tmpl) + xmlStrlen(xptr) + 2;
		tmp = (xmlChar*)xmlMalloc(size);
		if(tmp == NULL) {
		    xmlSecError(XMLSEC_ERRORS_HERE,
				XMLSEC_ERRORS_R_MALLOC_FAILED,
				"%d", size);
		    xmlXPathFreeContext(ctxt);
		    return(-1);	    
		}
		
		sprintf(tmp, tmpl, xptr + 1);
		type = xmlSecNodeSetTreeWithoutComments;
		res = xmlXPtrEval(tmp, ctxt);
		xmlFree(tmp);
	    }

	    if(res == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XML_FAILED,
			    "xmlXPtrEval(%s)", xptr + 1);
		xmlXPathFreeContext(ctxt);
		return(-1);	    
	    }

	    if((res->nodesetval == NULL) || (res->nodesetval->nodeNr == 0)) {
		/* TODO: it is warning, not an error! */
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_INVALID_NODESET,
			    "empty");
	    }

	    state->curNodeSet = xmlSecNodeSetCreate(state->curDoc, 
					    res->nodesetval,
					    type);
	    if(state->curNodeSet == NULL){
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecNodeSetCreate");	    
		xmlXPathFreeObject(res);
		xmlXPathFreeContext(ctxt);
		return(-1);
	    }
	    res->nodesetval = NULL;
	    
	    xmlXPathFreeObject(res);
	    xmlXPathFreeContext(ctxt);
	}
    }

    return(0);
}

/**
 * xmlSecTransformStateDestroyCurrentDoc:
 */
static void 
xmlSecTransformStateDestroyCurrentDoc(xmlSecTransformStatePtr state) {
    xmlSecAssert(state != NULL);

    if((state->curDoc != NULL) && (state->curDoc != state->initDoc)) {
        xmlFreeDoc(state->curDoc);
    }
    if((state->curNodeSet != NULL) && (state->curNodeSet != state->initNodeSet)) {
        xmlSecNodeSetDestroy(state->curNodeSet);
    }
    state->curDoc = NULL;
    state->curNodeSet = NULL;    
}

/**
 * xmlSecTransformCreateXml:
 *
 * Creates XML document from current state:
 *   1) if there is a pending c14n or binary transforms -- apply
 *   2) if curDoc == NULL and initUri != NULL then load uri
 *   3) if curDoc != NULL do nothing (no pending transforms)
 * otherwise initUir and curDoc are both null and it is an error
 */
static int  
xmlSecTransformCreateXml(xmlSecTransformStatePtr state) {
    int ret;

    xmlSecAssert2(state != NULL, -1);
    
    if((state->curDoc == NULL) && (state->initUri == NULL)) { 
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_DATA,
    		    "both doc and uri are null");
        return(-1);
    }

    if((state->curDoc == NULL) && (state->curFirstBinTransform == NULL)) {
	/* load XML document directly from file */
	state->curDoc = xmlSecParseFile(state->initUri);
	if(state->curDoc == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecParseFile(%s)", state->initUri);
	    return(-1);
	}
	state->curNodeSet = NULL;
    } else if((state->curFirstBinTransform != NULL) || (state->curC14NTransform != NULL)) { 
        /* 
         * bin transforms chain is defined or c14n is pending
         * the source is curDoc 
         */
        ret = xmlSecTransformCreateBin(state);
        if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecTransformCreateBin - %d", ret);
	    return(-1);
	}
	/* parse XML doc from memory */
	state->curDoc = xmlSecParseMemory(xmlBufferContent(state->curBuf), 
		    			  xmlBufferLength(state->curBuf), 1);
	if(state->curDoc == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecParseMemory");
	    return(-1);	    
	}
	/* do not forget to empty buffer! */
	xmlBufferEmpty(state->curBuf);	
    } else {
	/* 
	 * do nothing because curDoc != NULL and there is no pending 
	 * binary or c14n transforms
	 */
    }
    return(0);
}

/**
 * xmlSecTransformCreateBin:
 */
static int 
xmlSecTransformCreateBin(xmlSecTransformStatePtr state) {
    int ret;
    
    xmlSecAssert2(state != NULL, -1);
    
    if(state->curDoc != NULL) {
        ret = xmlSecTransformCreateBinFromXml(state);
    } else if(state->initUri != NULL) {
        ret = xmlSecTransformCreateBinFromUri(state);
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_INVALID_DATA,
    		    "both doc and uri are null");
	return(-1);
    }
    
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformCreateBinFromXml or xmlSecTransformCreateBinFromUri - %d", ret);
        return(-1);
    }
    return(0);
}

/**
 * xmlSecTransformCreateBinFromXml:
 */
static int  
xmlSecTransformCreateBinFromXml(xmlSecTransformStatePtr state) {
    xmlSecTransformPtr buffer;
    xmlOutputBufferPtr output;
    int ret;

    xmlSecAssert2(state != NULL, -1);
    xmlSecAssert2(state->curDoc != NULL, -1);
    
    /* first of all, add the memory buffer at the end */
    buffer = xmlSecTransformCreate(xmlSecMemBuf, 0, 0);
    if(buffer == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformCreate(xmlSecMemBuf)");
	return(-1);	
    }
    
    
    if(xmlSecBinTransformAddAfter(state->curLastBinTransform, buffer) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBinTransformAddAfter");
	xmlSecTransformDestroy(buffer, 1);
	return(-1);
    }
    if(state->curFirstBinTransform == NULL) state->curFirstBinTransform = buffer;
    state->curLastBinTransform = buffer;

    /* now create output buffer for c14n */
    output = xmlOutputBufferCreateIO((xmlOutputWriteCallback)xmlSecBinTransformWrite, 
				  (xmlOutputCloseCallback)xmlSecBinTransformFlush, 
				  (void*)state->curFirstBinTransform, NULL);
    if(output == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlOutputBufferCreateIO");
	return(-1);
    }

    /* 
     * by default (state->c14n == NULL) we use inclusive c14n:
     *
     * If the data object is a node-set and the next transform requires octets, 
     * the signature application MUST attempt to convert the node-set to an octet 
     * stream using Canonical XML [XML-C14N].  
     *
     * the story is different if the first 
     * transform is base64 decode:
     *
     * http://www.w3.org/TR/xmldsig-core/#sec-Base-64
     *
     * This transform requires an octet stream for input. If an XPath node-set 
     * (or sufficiently functional alternative) is given as input, then it is 
     * converted to an octet stream by performing operations logically equivalent 
     * to 1) applying an XPath transform with expression self::text(), then 2) 
     * taking the string-value of the node-set. Thus, if an XML element is 
     * identified by a barename XPointer in the Reference URI, and its content 
     * consists solely of base64 encoded character data, then this transform 
     * automatically strips away the start and end tags of the identified element 
     * and any of its descendant elements as well as any descendant comments and 
     * processing instructions. The output of this transform is an octet stream.
     */
    if((state->curC14NTransform == NULL) && 
	xmlSecTransformCheckId(state->curFirstBinTransform, xmlSecEncBase64Decode)) {
        ret = xmlSecTransformPreBase64Decode(state->curDoc->children, 
					     state->curNodeSet, output);
    } else {
        ret = xmlSecC14NTransformExecute(state->curC14NTransform, 
			 state->curDoc, state->curNodeSet, output);
        if(state->curC14NTransform != NULL) {
	    xmlSecTransformDestroy(state->curC14NTransform, 0);
	    state->curC14NTransform = NULL;
	}
    }    
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformPreBase64Decode or xmlSecC14NTransformExecute - %d", ret);
	xmlOutputBufferClose(output);
	return(-1);	
    }

    /* flush data in the buffer by closing it */    
    ret = xmlOutputBufferClose(output);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlOutputBufferClose");
	return(-1);	
    }

    /* "reassign" the buffer */
    if(state->curBuf != NULL) {
	xmlBufferEmpty(state->curBuf);
	xmlBufferFree(state->curBuf);
    }
    state->curBuf = xmlSecMemBufTransformGetBuffer(buffer, 1);
        
    /* cleanup */    
    xmlSecBinTransformDestroyAll(state->curFirstBinTransform);
    state->curFirstBinTransform = state->curLastBinTransform = NULL;
    xmlSecTransformStateDestroyCurrentDoc(state);
    return(0);
}

/**
 * xmlSecTransformCreateBinFromXml:
 */
static int  
xmlSecTransformCreateBinFromUri(xmlSecTransformStatePtr state) {
    xmlSecTransformPtr ptr;
    unsigned char buffer[XMLSEC_TRANSFORM_BUFFER_SIZE];
    int ret;

    xmlSecAssert2(state != NULL, -1);
    xmlSecAssert2(state->initUri != NULL, -1);

    /* add the uri load at the beginning */
    ptr = xmlSecTransformCreate(xmlSecInputUri, 0, 0);
    if(ptr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecTransformCreate(xmlSecInputUri)");
	return(-1);	
    }    
    
    ret = xmlSecInputUriTransformOpen(ptr, state->initUri);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecInputUriTransformOpen(%s) - %d", state->initUri, ret);
	xmlSecTransformDestroy(ptr, 1);
	return(-1);	
    }
    
    if(xmlSecBinTransformAddBefore(state->curFirstBinTransform, ptr) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecBinTransformAddBefore");
	xmlSecTransformDestroy(ptr, 1);
	return(-1);
    }
    if(state->curLastBinTransform == NULL) state->curLastBinTransform = ptr;
    state->curFirstBinTransform = ptr;
	
    /* empty the current buffer */
    xmlBufferEmpty(state->curBuf);
    
    do {
	ret = xmlSecBinTransformRead(state->curLastBinTransform, buffer, XMLSEC_TRANSFORM_BUFFER_SIZE);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecBinTransformRead - %d", ret);
	    return(-1);
	} else if(ret > 0) {
	    xmlBufferAdd(state->curBuf, buffer, ret);
	}
    } while(ret > 0);

    /* cleanup */
    xmlSecBinTransformDestroyAll(state->curFirstBinTransform);
    state->curFirstBinTransform = state->curLastBinTransform = NULL;
    
    return(0);
}

/**
 * xmlSecTransformPreBase64Decode:
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-Base-64:
 *
 * Base64 transform
 * This transform requires an octet stream for input. If an XPath node-set 
 * (or sufficiently functional alternative) is given as input, then it is 
 * converted to an octet stream by performing operations logically equivalent 
 * to 1) applying an XPath transform with expression self::text(), then 2) 
 * taking the string-value of the node-set. Thus, if an XML element is 
 * identified by a barename XPointer in the Reference URI, and its content 
 * consists solely of base64 encoded character data, then this transform 
 * automatically strips away the start and end tags of the identified element 
 * and any of its descendant elements as well as any descendant comments and 
 * processing instructions. The output of this transform is an octet stream.
 *
 */
static int
xmlSecTransformPreBase64DecodeWalk(xmlSecNodeSetPtr nodeSet, xmlNodePtr cur, 
				   xmlNodePtr parent ATTRIBUTE_UNUSED, 
				   void* data) {
    xmlSecAssert2(nodeSet != NULL, -1);
    xmlSecAssert2(cur != NULL, -1);
    xmlSecAssert2(data != NULL, -1);

    if(cur->type == XML_TEXT_NODE) {
	xmlOutputBufferWriteString((xmlOutputBufferPtr)data, 
				    (char*)(cur->content)); 
    }
    return(0);
}

static int 
xmlSecTransformPreBase64Decode(const xmlNodePtr node, xmlSecNodeSetPtr nodeSet, 
			       xmlOutputBufferPtr output) {
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(output != NULL, -1);

    if(nodeSet != NULL) {
	if(xmlSecNodeSetWalk(nodeSet, xmlSecTransformPreBase64DecodeWalk, output) < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecNodeSetWalk");
	    return(-1);
	}
    } else if(node->type == XML_ELEMENT_NODE) {
	cur = node->children;
	while(cur != NULL) {
	    ret = xmlSecTransformPreBase64Decode(cur, NULL, output);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "xmlSecTransformPreBase64Decode - %d", ret);
		return(-1);
	    }
	}
    } else if(node->type == XML_TEXT_NODE) { 
        xmlOutputBufferWriteString(output, (char*)node->content); 	
    }
    return(0);
}

