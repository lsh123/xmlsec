/** 
 * XMLSec library
 *
 * C14N transforms
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
#include <libxml/c14n.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/errors.h>

static const xmlChar xmlExcC14NNs[] = "http://www.w3.org/2001/10/xml-exc-c14n#";
static const xmlChar xmlExcC14NWithCommentsNs[] = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";


static xmlSecTransformPtr xmlSecC14NTransformCreate	(xmlSecTransformId id);
static void		xmlSecC14NTransformDestroy	(xmlSecTransformPtr transform);
static int 		xmlSecC14NTransformReadNode	(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int 		xmlSecC14NTransformExec		(xmlSecTransformPtr transform,
							 xmlDocPtr doc,
							 xmlSecNodeSetPtr nodes,
							 xmlOutputBufferPtr buffer);

static const struct _xmlSecTransformKlass xmlSecC14NInclusiveTransformId = {
    /* same as xmlSecTransformId */    
    BAD_CAST "c14n-inc",
    xmlSecTransformTypeC14N,		/* xmlSecTransformType type; */
    xmlSecTransformUsageC14NMethod | xmlSecTransformUsageDSigTransform,		/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/TR/2001/REC-xml-c14n-20010315", /* const xmlChar href; */

    xmlSecC14NTransformCreate, 		/* xmlSecTransformCreateMethod create; */
    xmlSecC14NTransformDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecC14NTransformReadNode,	/* xmlSecTransformReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */

    /* bin transforms */
    NULL,
    NULL,
    NULL,
    NULL,
    
    /* xml */
    NULL,    
    
    /* c14n methods */
    xmlSecC14NTransformExec		/* xmlSecC14NTransformExecuteMethod executeC14N; */
};
xmlSecTransformId xmlSecC14NInclusive = (xmlSecTransformId)&xmlSecC14NInclusiveTransformId;

static const struct _xmlSecTransformKlass xmlSecC14NInclusiveWithCommentsTransformId = {
    /* same as xmlSecTransformId */    
    BAD_CAST "c14n-inc-with-comments",
    xmlSecTransformTypeC14N,		/* xmlSecTransformType type; */
    xmlSecTransformUsageC14NMethod | xmlSecTransformUsageDSigTransform,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments", /* const xmlChar href; */

    xmlSecC14NTransformCreate, 		/* xmlSecTransformCreateMethod create; */
    xmlSecC14NTransformDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecC14NTransformReadNode,	/* xmlSecTransformReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */

    /* bin transforms */
    NULL,
    NULL,
    NULL,
    NULL,
    
    /* xml */
    NULL,    
    
    /* c14n methods */
    xmlSecC14NTransformExec		/* xmlSecC14NTransformExecuteMethod executeC14N; */
};
xmlSecTransformId xmlSecC14NInclusiveWithComments = (xmlSecTransformId)&xmlSecC14NInclusiveWithCommentsTransformId;

static const struct _xmlSecTransformKlass xmlSecC14NExclusiveTransformId = {
    /* same as xmlSecTransformId */    
    BAD_CAST "c14n-exc",
    xmlSecTransformTypeC14N,		/* xmlSecTransformType type; */
    xmlSecTransformUsageC14NMethod | xmlSecTransformUsageDSigTransform,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/10/xml-exc-c14n#", /* const xmlChar href; */

    xmlSecC14NTransformCreate, 		/* xmlSecTransformCreateMethod create; */
    xmlSecC14NTransformDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecC14NTransformReadNode,	/* xmlSecTransformReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    
    /* bin transforms */
    NULL,
    NULL,
    NULL,
    NULL,
    
    /* xml */
    NULL,    
    
    /* c14n methods */
    xmlSecC14NTransformExec		/* xmlSecC14NTransformExecuteMethod executeC14N; */
};
xmlSecTransformId xmlSecC14NExclusive = (xmlSecTransformId)&xmlSecC14NExclusiveTransformId;

static const struct _xmlSecTransformKlass xmlSecC14NExclusiveWithCommentsTransformId = {
    /* same as xmlSecTransformId */    
    BAD_CAST "c14n-exc-with-comments",
    xmlSecTransformTypeC14N,		/* xmlSecTransformType type; */
    xmlSecTransformUsageC14NMethod | xmlSecTransformUsageDSigTransform,		/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/10/xml-exc-c14n#WithComments", /* const xmlChar href; */

    xmlSecC14NTransformCreate, 		/* xmlSecTransformCreateMethod create; */
    xmlSecC14NTransformDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecC14NTransformReadNode,	/* xmlSecTransformReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */

    /* bin transforms */
    NULL,
    NULL,
    NULL,
    NULL,
    
    /* xml */
    NULL,    
    
    /* c14n methods */
    xmlSecC14NTransformExec		/* xmlSecC14NTransformExecuteMethod executeC14N; */
};
xmlSecTransformId xmlSecC14NExclusiveWithComments = (xmlSecTransformId)&xmlSecC14NExclusiveWithCommentsTransformId;

/**
 * xmlSecC14NTransformCreate:
 */
static xmlSecTransformPtr 
xmlSecC14NTransformCreate(xmlSecTransformId id) {
    xmlSecTransformPtr transform;

    xmlSecAssert2(id != NULL, NULL);
        
    if((id != xmlSecC14NInclusive) && 
       (id != xmlSecC14NInclusiveWithComments) &&
       (id != xmlSecC14NExclusive) && 
       (id != xmlSecC14NExclusiveWithComments)) {
       
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecC14NInclusive, xmlSecC14NInclusiveWithComments, xmlSecC14NExclusive, xmlSecC14NExclusiveWithComments");
	return(NULL);
    }
    
    transform = (xmlSecTransformPtr) xmlMalloc(sizeof(xmlSecTransform));  
    if (transform == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecTransform)=%d",
		    sizeof(xmlSecTransform));
	return(NULL);
    }
    memset(transform, 0, sizeof(xmlSecTransform));

    transform->id = id;
    return((xmlSecTransformPtr)transform);
}

/** 
 * xmlSecC14NTransformDestroy
 */
static void
xmlSecC14NTransformDestroy(xmlSecTransformPtr transform) {
    xmlSecTransformPtr ptr;

    xmlSecAssert(transform != NULL);

    if(!xmlSecTransformCheckId(transform, xmlSecC14NInclusive) &&
       !xmlSecTransformCheckId(transform, xmlSecC14NInclusiveWithComments) &&
       !xmlSecTransformCheckId(transform, xmlSecC14NExclusive) &&
       !xmlSecTransformCheckId(transform, xmlSecC14NExclusiveWithComments) ) {

	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecC14NInclusive, xmlSecC14NInclusiveWithComments, xmlSecC14NExclusive, xmlSecC14NExclusiveWithComments");
	return;
    }

    ptr = (xmlSecTransformPtr)transform;    
    if(ptr->reserved0 != NULL) {
	xmlFree(ptr->reserved0);
    }    
    
    if(ptr->reserved3 != NULL) {
	xmlFree(ptr->reserved3);
    }
    
    memset(ptr, 0, sizeof(xmlSecTransform));
    xmlFree(ptr);    
}

/** 
 * xmlSecC14NTransformReadNode:
 */
static int
xmlSecC14NTransformReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    xmlSecTransformPtr ptr;
    xmlNodePtr node;
    xmlChar *buffer;
    xmlChar *p;
    size_t count, len;
    xmlChar **nsList;        
    
    xmlSecAssert2(transform != NULL, -1);

    if(!xmlSecTransformCheckId(transform, xmlSecC14NInclusive) &&
       !xmlSecTransformCheckId(transform, xmlSecC14NInclusiveWithComments) &&
       !xmlSecTransformCheckId(transform, xmlSecC14NExclusive) &&
       !xmlSecTransformCheckId(transform, xmlSecC14NExclusiveWithComments) ) {

	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecC14NInclusive, xmlSecC14NInclusiveWithComments, xmlSecC14NExclusive, xmlSecC14NExclusiveWithComments");    
	return(-1);
    }

    ptr = (xmlSecTransformPtr)transform;
    if(ptr->reserved0 != NULL) {	
	xmlFree(ptr->reserved0); 
	ptr->reserved0 = NULL;
    }
    if(ptr->reserved3 != NULL) {
	xmlFree(ptr->reserved3);
	ptr->reserved3 = NULL;
    }
    
    if((transformNode == NULL) || 
	xmlSecTransformCheckId(transform, xmlSecC14NInclusive) ||
        xmlSecTransformCheckId(transform, xmlSecC14NInclusiveWithComments)) {
	/* do nothing - there is no addionatal idr for inclusive comments */
	return(0);
    }

    /* TODO: throw an error if any other children is present */
    node = xmlSecFindChild(transformNode, BAD_CAST "InclusiveNamespaces", xmlExcC14NNs);
    if(node == NULL) {
	node = xmlSecFindChild(transformNode, BAD_CAST "InclusiveNamespaces", xmlExcC14NWithCommentsNs);
    }
    if(node == NULL) {
	/* no namespaces :( */
	return(0);
    }
    
    ptr->reserved0 = buffer = xmlGetProp(node, BAD_CAST "PrefixList");
    if(buffer == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_NODE_ATTRIBUTE,
		    "<InclusiveNamespaces /> node has no PrefixList attribute");
	return(-1);
    }
    
    count = 0;
    len = 0;
    p = buffer;
    while((*p) != '\0') {
	if(((*p) == ' ') && (len > 0)) {
	    len = 0;
	    ++count;
	} else if((*p) != ' ') {
	    ++len;
	}
	++p;
    }
    
    ptr->reserved3 = nsList = (xmlChar**)xmlMalloc(sizeof(xmlChar*) * (count + 2));
    if(ptr->reserved3 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", sizeof(xmlChar*) * (count + 2));
	return(-1);
    }
    memset(nsList, 0, sizeof(xmlChar*) * (count + 2));

    count = 0;
    len = 0;
    p = buffer;
    nsList[0] = p;
    while((*p) != '\0') {
	if(((*p) == ' ') && (len > 0)) {
	    (*p) = '\0';
	    len = 0;
	    nsList[++count] = p + 1;
	} else if((*p) != ' ') {
	    ++len;
	}
	++p;
    }        
    return(0);
    
}

/** 
 * xmlSecC14NTransformExec:
 */
static int
xmlSecC14NTransformExec(xmlSecTransformPtr transform, xmlDocPtr doc,
			xmlSecNodeSetPtr nodes, xmlOutputBufferPtr buffer) {
    int ret;


    xmlSecAssert2(doc!= NULL, -1);
    xmlSecAssert2(buffer != NULL, -1);

    if(transform == NULL) {
	/* the default c14n transform */
	ret = xmlC14NExecute(doc, 
			(xmlC14NIsVisibleCallback)xmlSecNodeSetContains, 
			nodes, 
			0, NULL, 0, buffer);
    } else if(xmlSecTransformCheckId(transform, xmlSecC14NInclusive)) {    
    	ret = xmlC14NExecute(doc, 
			(xmlC14NIsVisibleCallback)xmlSecNodeSetContains, 
			nodes, 
			0, NULL, 0, buffer);
    } else if(xmlSecTransformCheckId(transform, xmlSecC14NInclusiveWithComments)) {
	 ret = xmlC14NExecute(doc, 
			(xmlC14NIsVisibleCallback)xmlSecNodeSetContains, 
			nodes, 
			0, NULL, 1, buffer); 
    } else if(xmlSecTransformCheckId(transform, xmlSecC14NExclusive)) {
	ret = xmlC14NExecute(doc, 
			(xmlC14NIsVisibleCallback)xmlSecNodeSetContains, 
			nodes, 
			1, (xmlChar**)(transform->reserved3), 0, buffer);
    } else if(xmlSecTransformCheckId(transform, xmlSecC14NExclusiveWithComments)) {
	ret = xmlC14NExecute(doc, 
			(xmlC14NIsVisibleCallback)xmlSecNodeSetContains, 
			nodes, 
			1, (xmlChar**)(transform->reserved3), 1, buffer);
    } else {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecC14NInclusive, xmlSecC14NInclusiveWithComments, xmlSecC14NExclusive, xmlSecC14NExclusiveWithComments");    
	return(-1);
    }
    
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlC14NExecute");
	return(-1);
    }    
    return(0);
}

/**
 * xmlSecC14NExclAddInclNamespaces:
 * @transformNode: the pointer to <dsig:Transform> node.
 * @prefixList: the white space delimited  list of namespace prefixes, 
 *		where "#default" indicates the default namespace
 *
 * Adds "inclusive" namespaces to the ExcC14N transform node @transformNode.
 *
 * Returns 0 if success or a negative value otherwise.
 */
int		
xmlSecC14NExclAddInclNamespaces(xmlNodePtr transformNode, const xmlChar *prefixList) {
    xmlNodePtr node;

    xmlSecAssert2(transformNode != NULL, -1);    
    xmlSecAssert2(prefixList != NULL, -1);

    node = xmlSecFindChild(transformNode, BAD_CAST "InclusiveNamespaces", xmlExcC14NNs);
    if(node != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "InclusiveNamespace");
	return(-1);
    }
    
    node = xmlSecAddChild(transformNode, BAD_CAST "InclusiveNamespaces", xmlExcC14NNs);
    if(node == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecAddChild(\"InclusiveNamespaces\")");
	return(-1);
    }    
    
    xmlSetProp(node, BAD_CAST "PrefixList", prefixList);    
    return(0);
}


