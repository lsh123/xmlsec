/** 
 * XML Security Library
 *
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

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/transforms.h>

#include <xmlsec/io.h>
#include <xmlsec/membuf.h>

#define XMLSEC_TRANSFORM_BUFFER_SIZE    1024


static xmlSecTransformId xmlSecAllTransforms[100];

/* internal functions */
static int  xmlSecTransformStateParseUri(xmlSecTransformStatePtr state, const char *uri);
static void xmlSecTransformStateDestroyCurrentDoc(xmlSecTransformStatePtr state);
static int  xmlSecTransformCreateXml(xmlSecTransformStatePtr state);
static int  xmlSecTransformCreateBin(xmlSecTransformStatePtr state);
static int  xmlSecTransformCreateBinFromXml(xmlSecTransformStatePtr state);
static int  xmlSecTransformCreateBinFromUri(xmlSecTransformStatePtr state);
static int xmlSecTransformPreBase64Decode(const xmlNodePtr node, const xmlNodeSetPtr nodeSet, 
					xmlOutputBufferPtr output);

/** 
 * Hi-level functions
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

#ifndef XMLSEC_NO_XPATHALT 
    xmlSecAllTransforms[i++] =  xmlSecXPathAlt;
#endif /* XMLSEC_NO_XPATHALT */    
    
    /* Input/memory buffer */
    xmlSecAllTransforms[i++] = xmlSecInputUri;
    xmlSecAllTransforms[i++] = xmlSecMemBuf;

    /* MUST be the last in the list */
    xmlSecAllTransforms[i++] = xmlSecTransformUnknown;
}

/**
 * xmlSecTransformsNodeRead:
 * @state:
 * @transformsNode:
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
 */
int
xmlSecTransformsNodeRead(xmlSecTransformStatePtr state, xmlNodePtr transformsNode) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformsNodeRead";
    xmlNodePtr cur;
    xmlSecTransformPtr transform;
    int ret;    
        
    if((state == NULL) || (transformsNode == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: state or transformsNode is null\n", 
	    func);	
#endif
	return(-1);	    
    }
    
    cur = xmlSecGetNextElementNode(transformsNode->children);
    while((cur != NULL) && xmlSecCheckNodeName(cur, BAD_CAST "Transform", xmlSecDSigNs)) {
	transform = xmlSecTransformNodeRead(cur, xmlSecUsageDSigTransform, 0);
	if(transform == NULL) {
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to read \"Transform\"\n",
		func);
#endif	    
	    return(-1);
	}
	ret = xmlSecTransformStateUpdate(state, transform);
	if(ret < 0){
#ifdef XMLSEC_DEBUG    
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to add \"Transform\"\n",
		func);
#endif	    
	    xmlSecTransformDestroy(transform, 1);
	    return(-1);
	}
	cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
#ifdef XMLSEC_DEBUG    
	xmlGenericError(xmlGenericErrorContext,
	    "%s: found unexpected node\n",
	    func);
#endif	    
	return(-1);
    }    
    return(0);
}

/** 
 * xmlSecTransformNodeRead:
 * @transformNode:
 * @usage:
 * @dontDestroy:
 *
 * Reads transform from current transform node as follows:
 *   1) reads "Algorithm" attribute
 *   2) checks the list of known algorithms
 *   3) calls transform create method
 *   4) calls transform read transform node method
 *
 */
xmlSecTransformPtr	
xmlSecTransformNodeRead(xmlNodePtr transformNode, xmlSecTransformUsage usage,
			int dontDestroy) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformNodeRead";
    xmlChar *href;
    xmlSecTransformId id;
    xmlSecTransformPtr transform;
    int ret;
    
    if(transformNode == NULL){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transformNode is null\n", 
	    func);	
#endif
	return(NULL);	
    }
    
    href = xmlGetProp(transformNode, BAD_CAST "Algorithm");
    if(href == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: \"Algorithm\" is required attribute for any transform node\n", 
	    func);	
#endif
	return(NULL);		
    }
    
    id = xmlSecTransformFind(href);    
    if(id == xmlSecTransformUnknown) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: id \"%s\" is unknown\n", 
	    func, href);	
#endif
	xmlFree(href);
	return(NULL);		
    }
    
    transform = xmlSecTransformCreate(id, usage, dontDestroy);
    if(!xmlSecTransformIsValid(transform)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create transform for id \"%s\"\n", 
	    func, href);	
#endif
	xmlFree(href);
	return(NULL);		
    }
    
    ret = xmlSecTransformRead(transform, transformNode);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed read transform for id \"%s\"\n", 
	    func, href);
#endif
	xmlSecTransformDestroy(transform, 1);
	xmlFree(href);
	return(NULL);		
    }
    
    xmlFree(href);   
    return(transform);
}

/**
 * xmlSecTransformNodeWrite:
 * @transformNode:
 * @id:
 *
 * Writes transform Agorithm in the transform node as follows
 */
int
xmlSecTransformNodeWrite(xmlNodePtr transformNode, xmlSecTransformId id) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformNodeWrite";
    
    if((transformNode == NULL) && (id == xmlSecTransformUnknown)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transformNode is null or transform is invalid\n", 
	    func);	
#endif
	return(-1);	
    }

    
    if(xmlSetProp(transformNode, BAD_CAST "Algorithm", id->href) == NULL) {	
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to set \"Algorithm\" attribute for transform node\n", 
	    func);	
#endif
	return(-1);	
    }

    return(0);
}

/**
 * Transform Info
 */ 
/**
 * xmlSecTransformInfoByHref:
 * @id:		
 *
 * Searches the table of known transforms for transform with given href
 *
 */ 
xmlSecTransformId
xmlSecTransformFind(const xmlChar* href) {
    xmlSecTransformId *ptr;
    
    ptr = xmlSecAllTransforms;
    while((*ptr) != xmlSecTransformUnknown) {
	if(xmlStrEqual((*ptr)->href, href)) {
	    return(*ptr);
	}
	++ptr;
    }
    return(NULL);
}

/**
 * Transform 
 */ 
/**
 * xmlSecTransformCreate:
 * @ptr:
 * @usage:
 * @dontDestroy:	the flag that controls wherther the transforms
 *			can destroy the transforms automatically
 *
 * Creates new transform from the transform id object
 */ 
xmlSecTransformPtr	
xmlSecTransformCreate(xmlSecTransformId id, xmlSecTransformUsage usage, 
		      int dontDestroy) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformCreate";
    xmlSecTransformPtr transform;
    
    if((id == xmlSecTransformUnknown) || (id->create == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform id or create method is null\n",
	    func);	
#endif
	return(NULL);	
    }

    if((id->usage & usage) != usage) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: id could not be used as %d\n", 
	    func, usage);	
#endif
	return(NULL);		
    }

        
    transform = id->create(id);
    if(transform == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform creation failed\n",
	    func);	
#endif
	return(NULL);	
    }
    transform->dontDestroy = dontDestroy;
    return(transform);
}

/**
 * xmlSecTransformDestroy:
 * @transform:
 * @forceDestroy:
 *
 * Destroys transform
 */
void
xmlSecTransformDestroy(xmlSecTransformPtr transform, int forceDestroy) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformDestroy";
    
    if((!xmlSecTransformIsValid(transform)) || (transform->id->destroy == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid or destroy function is missed!\n",
	    func);	
#endif
	return;
    }
    
    /*
     * Special case for binary transforms: need to remove from chain 
     */
    if(transform->id->type == xmlSecTransformTypeBinary) {
	xmlSecBinTransformRemove(transform);
    }

    if((transform->dontDestroy) && (!forceDestroy)){
	/* requested do not destroy trasnform */
	return;
    }    
    transform->id->destroy(transform);
}

/** 
 * xmlSecTransformRead:
 * @transform:
 * @transformNode:
 *
 * Reads data about transform from the node where transform is declared.
 */
int
xmlSecTransformRead(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformRead";

    if(!xmlSecTransformIsValid(transform)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return(-1);
    }
    if(transform->id->read != NULL) {
	return(transform->id->read(transform, transformNode));
    }
    return(0);
}

/**
 * Binary transform
 */ 
/**
 * xmlSecTransformAddKey:
 *
 * Wrapper for xmlSecBinTransformPtr addBinKey method
 */
int
xmlSecTransformAddKey(xmlSecTransformPtr transform, xmlSecKeyPtr key) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformAddKey";
    xmlSecBinTransformId id;
        
    if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeBinary)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
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
 *
 *
 * Wrapper for xmlSecBinTransformPtr readBin method
 */
int
xmlSecBinTransformRead(xmlSecTransformPtr transform, 
		       unsigned char *buf, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecBinTransformRead";
    xmlSecBinTransformId id;
    
    if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeBinary)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return(-1);
    }
    
    id = ((xmlSecBinTransformId)(transform->id));
    if(id->readBin != NULL) {
	return((id->readBin)((xmlSecBinTransformPtr)transform, buf, size));
    }
    return(0);
}

/**
 * xmlSecBinTransformWrite
 *
 * Wrapper for xmlSecBinTransformPtr writeBin method
 */
int
xmlSecBinTransformWrite(xmlSecTransformPtr transform, 
			const unsigned char *buf, size_t size) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecBinTransformWrite";
    xmlSecBinTransformId id;
    
    if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeBinary)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return(-1);
    }
    
    id = ((xmlSecBinTransformId)(transform->id));
    if(id->writeBin != NULL) {
	return((id->writeBin)((xmlSecBinTransformPtr)transform, buf, size));
    }
    return(0);
}

/**
 * xmlSecBinTransformFlush
 *
 *
 * Wrapper for xmlSecBinTransformPtr flushBin method
 */
int
xmlSecBinTransformFlush(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecBinTransformFlush";
    xmlSecBinTransformId id;
    
    if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeBinary)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return(-1);
    }
    
    id = ((xmlSecBinTransformId)(transform->id));
    if(id->flushBin != NULL) {
	return((id->flushBin)((xmlSecBinTransformPtr)transform));
    }
    return(0);
}

/**
 * xmlSecBinTransformAddAfter
 *
 * Adding new transform in the chain after current transform
 */
xmlSecTransformPtr	
xmlSecBinTransformAddAfter(xmlSecTransformPtr curTransform, 
			xmlSecTransformPtr newTransform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecBinTransformAddAfter";
    xmlSecBinTransformPtr c;
    xmlSecBinTransformPtr n;
    
    if(((curTransform != NULL) && !xmlSecTransformCheckType(curTransform, xmlSecTransformTypeBinary)) ||
       !xmlSecTransformCheckType(newTransform, xmlSecTransformTypeBinary)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: new transform is invalid\n",
	    func);	
#endif
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
 *
 * Adding new transform in the chain before current transform
 */
xmlSecTransformPtr	
xmlSecBinTransformAddBefore(xmlSecTransformPtr curTransform, 
			    xmlSecTransformPtr newTransform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecBinTransformAddBefore";
    xmlSecBinTransformPtr c;
    xmlSecBinTransformPtr n;

    if(((curTransform != NULL) && !xmlSecTransformCheckType(curTransform, xmlSecTransformTypeBinary)) ||
       !xmlSecTransformCheckType(newTransform, xmlSecTransformTypeBinary)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: new transform is invalid\n",
	    func);	
#endif
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
 * xmlSecBinTransformRemove
 *
 * Removes transform from the chain. This method MUST be called by any 
 * bin transform id
 */
void
xmlSecBinTransformRemove(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecBinTransformRemove";
    xmlSecBinTransformPtr t;
    
    if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeBinary)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
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
 * xmlSecBinTransformDestroyAll
 *
 * Destroys all transforms in the chain
 */
void
xmlSecBinTransformDestroyAll(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecBinTransformDestroyAll";
    xmlSecBinTransformPtr t;

    if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeBinary)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
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

void	
xmlSecBinTransformSetEncrypt(xmlSecTransformPtr transform, int encrypt) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecBinTransformSetEncrypt";
    xmlSecBinTransformPtr t;

    if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeBinary)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return;
    }
    
    t = (xmlSecBinTransformPtr)transform;
    t->encode = encrypt;
}

    
/** 
 * XML Transform
 */
/**
 * xmlSecXmlTransformExecute
 *
 *
 */
int
xmlSecXmlTransformExecute(xmlSecTransformPtr transform, xmlDocPtr ctxDoc,
			  xmlDocPtr *doc, xmlNodeSetPtr *nodes) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecXmlTransformExecute";
    xmlSecXmlTransformId id;
    
    if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeXml)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif
	return(-1);
    }
    
    id = ((xmlSecXmlTransformId)(transform->id));
    if(id->executeXml != NULL) {
	return((id->executeXml)((xmlSecXmlTransformPtr)transform, ctxDoc, 
				 doc, nodes));
    }
    return(0);
}

/**
 * C14N Transform
 */ 
/**
 * xmlSecC14NTransformExecute
 *
 *
 */
int	
xmlSecC14NTransformExecute(xmlSecTransformPtr transform,
			   xmlDocPtr doc, xmlNodeSetPtr nodes,
			   xmlOutputBufferPtr buffer) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecC14NTransformExecute";
    xmlSecC14NTransformId id;  
    
    if(transform != NULL) {
	if(!xmlSecTransformCheckType(transform, xmlSecTransformTypeC14N)) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: transform is invalid\n",
		func);	
#endif
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


/**
 * Transforms State
 */
/**
 * xmlSecTransformStateCreate
 * @doc:
 * @nodeSet:
 * @uri:
 *
 */
xmlSecTransformStatePtr	
xmlSecTransformStateCreate(xmlDocPtr doc, xmlNodeSetPtr nodeSet, const char *uri) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformStateCreate";
    xmlSecTransformStatePtr state;
    int ret;
    /*
     * Allocate a new xmlSecTransformState and fill the fields.
     */
    state = (xmlSecTransformStatePtr) xmlMalloc(sizeof(xmlSecTransformState));
    if(state == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: xmlSecTransformState malloc failed\n",
	    func);	
#endif 	    
	return(NULL);
    }
    memset(state, 0, sizeof(xmlSecTransformState));
    
    state->curBuf = xmlBufferCreate();
    if(state->curBuf == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: unable to create memory buffer\n",
	    func);
#endif	    
	xmlSecTransformStateDestroy(state);
        return(NULL);
    }

    state->initDoc = doc;
    state->initNodeSet = nodeSet;
    ret = xmlSecTransformStateParseUri(state, uri);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: uri parsing failed\n",
	    func);
#endif	    
	xmlSecTransformStateDestroy(state);
    	return(NULL);
    }
        
    return(state);     
}

/**
 * xmlSecTransformStateDestroy
 * @state:
 *
 * Destroys the transform state object
 */
void
xmlSecTransformStateDestroy(xmlSecTransformStatePtr state) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformStateDestroy";

    if(state == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: state is null\n",
	    func);	
#endif
	return;
    }
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
 * xmlSecTransformStateUpdate
 * 
 * @state:
 * @transform:
 *
 * Updates the current state with transform. Note all transforms are
 * applied immidiatelly!
 */
int
xmlSecTransformStateUpdate(xmlSecTransformStatePtr state, xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformStateUpdate";
    int ret;
    
    if((state == NULL) || !xmlSecTransformIsValid(transform)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: state or transform is null\n",
	    func);	
#endif
	return(-1);
    }
    
    switch(transform->id->type) {
    case xmlSecTransformTypeBinary:     	
	    /* simply add transform to the chain */
    	    transform = xmlSecBinTransformAddAfter(state->curFirstBinTransform, 
					     transform);
	    if(transform == NULL) {
#ifdef XMLSEC_DEBUG
    		xmlGenericError(xmlGenericErrorContext,
		    "%s: failed to add trasnform\n",
		    func);	
#endif
		return(-1);
	    }
	    if(state->curFirstBinTransform == NULL) {
		state->curFirstBinTransform = transform;
	    }
	    state->curLastBinTransform = transform;
	    break;
    case xmlSecTransformTypeXml: {
	xmlDocPtr doc;
	xmlNodeSetPtr nodes;
	
        ret = xmlSecTransformCreateXml(state);
        if(ret < 0) {
#ifdef XMLSEC_DEBUG
            xmlGenericError(xmlGenericErrorContext,
        	"%s: xml doc creation failed\n",
		func);	
#endif
	    return(-1);
	}
	
	doc = state->curDoc;
	nodes = state->curNodeSet;
	
	ret = xmlSecXmlTransformExecute(transform, state->initDoc, &doc, &nodes);
	if(ret < 0) {
#ifdef XMLSEC_DEBUG
            xmlGenericError(xmlGenericErrorContext,
        	"%s: xml transform failed\n",
		func);	
#endif
	    return(-1);
	}
	xmlSecTransformDestroy(transform, 0);
	if(doc != state->curDoc) {
	    xmlSecTransformStateDestroyCurrentDoc(state);
	} else if(nodes != state->curNodeSet) {
	    if((state->curNodeSet != NULL) && (state->curNodeSet != state->initNodeSet)) {
    		xmlXPathFreeNodeSet(state->curNodeSet);
	    }
	}	
	state->curDoc = doc;
	state->curNodeSet = nodes;
    	break;
	}
    case xmlSecTransformTypeC14N:
	ret = xmlSecTransformCreateXml(state);
	if(ret < 0) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
	        "%s: xml doc creation failed\n",
		func);	
#endif
	    return(-1);
	}
	state->curC14NTransform = transform;
	break;
    default:
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: unknown transform type %d\n",
	    func, transform->id->type);	
#endif
	return(-1);	    
    }
    return(0);
}

/**
 * xmlSecTransformStateFinal
 *
 * @state:
 * @type:
 */
int
xmlSecTransformStateFinal(xmlSecTransformStatePtr state, xmlSecTransformResult type) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformStateFinal";
    int ret;
    
    if(state == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: state is null\n",
	    func);	
#endif
	return(-1);
    }
    
    switch(type) {
    case xmlSecTransformResultBinary:
	ret = xmlSecTransformCreateBin(state);
	break;
    case xmlSecTransformResultXml:
	ret = xmlSecTransformCreateXml(state);
	break;
    default:
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: unknown result type %d\n",
	    func, type);	
#endif
	return(-1);	
    }    

    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create result of type %d\n",
	    func, type);	
#endif
	return(-1);	
    }
    return(0);
}

/**
 * xmlSecTransformStateParseUri:
 * @state:
 * @uri:
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
 * TODO: add full xpointer support
 */
static int 
xmlSecTransformStateParseUri(xmlSecTransformStatePtr state, const char *uri) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformStateParseUri";
    int len;
    char *ptr;
    char *id;
    xmlNodePtr cur;
    int withComments;
    
    if(state == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: state is null\n",
	    func);	
#endif
	return(-1);
    }
    
    if(uri == NULL) {
	state->curDoc = state->initDoc;
	state->curNodeSet = state->initNodeSet;
	return(0);
    } 
    
    len = strlen(uri);
    if(len == 0) {
	/* 
	 * create node set w/o comments: 
	 * TODO: optimize! 
	 */
	state->curDoc = state->initDoc;
	state->curNodeSet = 
	    xmlSecGetChildNodeSet(xmlDocGetRootElement(state->initDoc), NULL, 0);
	if(state->curNodeSet == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to create node set\n",
		func);	
#endif
	    return(-1);
	}
	return(0);
    }

    
    state->initUri = (char*)xmlMalloc(sizeof(char) * (len + 1));
    if(state->initUri == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: uri malloc failed (%d bytes)\n",
	    func, len + 1);	
#endif
	return(-1);
    }
    strcpy(state->initUri, uri);
        
    ptr = strchr(state->initUri, '#');
    if(ptr == NULL) {
	/* this is a simple uri, leave it alone for now */
	return(0);
    }
    
    /* this is a uri with '#' */
    *(ptr++) = '\0';
    
    /* if the uri is not empty, need to load document */
    if(strlen(state->initUri) > 0) {
	state->curDoc = xmlSecParseFile(state->initUri); 
	if(state->curDoc == NULL) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to load uri=\"%s\"\n",
		func, state->initUri);	
#endif
	    return(-1);	    
	}
    } else {
	state->curDoc = state->initDoc; 
    }
    
    /* 
     * the document loaded successfully, now let's try 
     * to understand what do we have 
     */
    if(strcmp(ptr, "xpointer(/)") == 0) {
	return(0);
    }
    
    if(strncmp(ptr, "xpointer(id('", 13) == 0) { 
	id = ptr + 13;
	ptr = strchr(id, '\'');
	if((ptr == NULL) || (strcmp(ptr, "\'))") != 0)) {
#ifdef XMLSEC_DEBUG
    	    xmlGenericError(xmlGenericErrorContext,
		"%s: bad xpointer(id(\'<id>\')) format\n",
		func);	
#endif
	    return(-1);	    	    
	}
	(*ptr) = '\0';
	withComments = 1;
    } else {
	id = ptr;
	withComments = 0;
    }
    
    cur = xmlSecFindNodeById(state->curDoc->children, BAD_CAST id);
    if(cur == NULL) {
#ifdef XMLSEC_DEBUG
    	xmlGenericError(xmlGenericErrorContext,
	    "%s: unable to find node in the document\n",
	    func);	
#endif
	    return(-1);	    	    
    }
    

    state->curNodeSet = xmlSecGetChildNodeSet(cur, NULL, withComments);
    if(state->curNodeSet == NULL) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create node set for node\n",
	    func);
#endif
	return(-1);
    }

    return(0);
}

/**
 * xmlSecTransformStateDestroyCurrentDoc:
 * @state:
 *
 * Destroys the current doc and nodeSet if they are not the same as
 * original ones.
 */
static void 
xmlSecTransformStateDestroyCurrentDoc(xmlSecTransformStatePtr state) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformStateDestroyCurrentDoc";

    if(state == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: state is null\n",
	    func);	
#endif
	return;
    }

    if((state->curDoc != NULL) && (state->curDoc != state->initDoc)) {
        xmlFreeDoc(state->curDoc);
    }
    if((state->curNodeSet != NULL) && (state->curNodeSet != state->initNodeSet)) {
        xmlXPathFreeNodeSet(state->curNodeSet);
    }
    state->curDoc = NULL;
    state->curNodeSet = NULL;    
}

/**
 * xmlSecTransformCreateXml:
 * @state: 
 *
 * Creates XML document from current state:
 *   1) if there is a pending c14n or binary transforms -- apply
 *   2) if curDoc == NULL and initUri != NULL then load uri
 *   3) if curDoc != NULL do nothing (no pending transforms)
 * otherwise initUir and curDoc are both null and it is an error
 */
static int  
xmlSecTransformCreateXml(xmlSecTransformStatePtr state) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformCreateXml";
    int ret;

    if(state == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: state is null\n",
	    func);	
#endif
	return(-1);
    }
    
    if((state->curDoc == NULL) && (state->initUri == NULL)) { 
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: both curDoc and uri are null\n",
	    func);
        return(-1);
    }

    if((state->curDoc == NULL) && (state->curFirstBinTransform == NULL)) {
	/* load XML document directly from file */
	state->curDoc = xmlSecParseFile(state->initUri);
	if(state->curDoc == NULL) {
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext,
	        "%s: unable to load xml file \"%s\"\n", 
	        func, state->initUri);
#endif	    
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
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext,
	        "%s: failed to dump results to memory\n",
		func);
#endif	    
	    return(-1);
	}
	/* parse XML doc from memory */
	state->curDoc = xmlSecParseMemory(xmlBufferContent(state->curBuf), 
		    			  xmlBufferLength(state->curBuf), 1);
	if(state->curDoc == NULL) {
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext,
	        "%s: failed to load xml from memory\n",
		func);
#endif	    
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
 * @state: 
 *
 * Creates binary buffer from current state
 */
static int 
xmlSecTransformCreateBin(xmlSecTransformStatePtr state) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformCreateBin";
    int ret;
    
    if(state == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: state is null\n",
	    func);	
#endif
	return(-1);
    }
    
    if(state->curDoc != NULL) {
        ret = xmlSecTransformCreateBinFromXml(state);
    } else if(state->initUri != NULL) {
        ret = xmlSecTransformCreateBinFromUri(state);
    } else {
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: both doc and uri are null\n",
	    func);
	return(-1);
    }
    
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
    	    "%s: failed to dump results to memory\n",
	    func);
#endif	    
        return(-1);
    }
    return(0);
}

/**
 * xmlSecTransformCreateBinFromXml:
 * @state:
 *
 * Creates binary buffer from current XML Doc
 *
 */
static int  
xmlSecTransformCreateBinFromXml(xmlSecTransformStatePtr state) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformCreateBinFromXml";
    xmlSecTransformPtr buffer;
    xmlOutputBufferPtr output;
    int ret;
    
    if((state == NULL) || (state->curDoc == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: state or curDoc is null\n",
	    func);	
#endif
	return(-1);
    }
    
    /* first of all, add the memory buffer at the end */
    buffer = xmlSecTransformCreate(xmlSecMemBuf, 0, 0);
    if(buffer == NULL) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create memory buffer\n",
	    func);
#endif	    
	return(-1);	
    }
    
    
    if(xmlSecBinTransformAddAfter(state->curLastBinTransform, buffer) == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: unable to add memory buffer to the chain\n",
	    func);
#endif	    
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
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s:  failed to create output buffer\n",
	    func);
#endif	    
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
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: c14n id failed\n",
	    func);
#endif	    
	xmlOutputBufferClose(output);
	return(-1);	
    }

    /* flush data in the buffer by closing it */    
    ret = xmlOutputBufferClose(output);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: buffer flush failed\n",
	    func);
#endif	    
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
 * @state:
 *
 * Creates binary buffer from init Uri
 *
 */
static int  
xmlSecTransformCreateBinFromUri(xmlSecTransformStatePtr state) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformCreateBinFromUri";
    xmlSecTransformPtr ptr;
    unsigned char buffer[XMLSEC_TRANSFORM_BUFFER_SIZE];
    int ret;

    if((state == NULL) || (state->initUri == NULL)){
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: state or initUrl is null\n",
	    func);	
#endif
	return(-1);
    }

    /* add the uri load at the beginning */
    ptr = xmlSecTransformCreate(xmlSecInputUri, 0, 0);
    if(ptr == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create uri transform\n",
	    func);
#endif	    
	return(-1);	
    }    
    
    ret = xmlSecInputUriTransformOpen(ptr, state->initUri);
    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to open uri \"%s\"\n",
	    func, state->initUri);
#endif	    
	xmlSecTransformDestroy(ptr, 1);
	return(-1);	
    }
    
    if(xmlSecBinTransformAddBefore(state->curFirstBinTransform, ptr) == NULL) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: unable to add uri transform\n",
	    func);
#endif	    
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
#ifdef XMLSEC_DEBUG
	    xmlGenericError(xmlGenericErrorContext,
		"%s: failed to read from binary trasnforms chain\n",
		func);
#endif	    
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
 * @node:
 * @nodes:
 * @output:
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
xmlSecTransformPreBase64Decode(const xmlNodePtr node, const xmlNodeSetPtr nodeSet, 
			       xmlOutputBufferPtr output) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecTransformPreBase64Decode";
    xmlNodePtr cur;
    int ret;

    if((node == NULL) || (output == NULL)) {
#ifdef XMLSEC_DEBUG
	xmlGenericError(xmlGenericErrorContext,
	    "%s: cur or output is null\n",
	    func);
#endif	    
	return(-1);
    }    
    
    if(nodeSet != NULL) {
	int i;
	/* simply walk thru all TEXT nodes */	
	for(i = 0; i < nodeSet->nodeNr; ++i) {
	    cur = nodeSet->nodeTab[i];
	    if(cur->type == XML_TEXT_NODE) {
                xmlOutputBufferWriteString(output, (char*)(cur->content)); 
	    }
	}
    } else if(node->type == XML_ELEMENT_NODE) {
	cur = node->children;
	while(cur != NULL) {
	    ret = xmlSecTransformPreBase64Decode(cur, NULL, output);
	    if(ret < 0) {
#ifdef XMLSEC_DEBUG
		xmlGenericError(xmlGenericErrorContext,
		    "%s: recursion failed\n",
		    func);
#endif	    
		return(-1);
	    }
	}
    } else if(node->type == XML_TEXT_NODE) { 
        xmlOutputBufferWriteString(output, (char*)node->content); 	
    }
    return(0);
}

