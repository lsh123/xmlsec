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

static int		xmlSecC14NTransformInitialize	(xmlSecTransformPtr transform);
static void		xmlSecC14NTransformFinalize	(xmlSecTransformPtr transform);
static int 		xmlSecC14NTransformReadNode	(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int 		xmlSecC14NTransformExec		(xmlSecTransformPtr transform,
							 xmlDocPtr doc,
							 xmlSecNodeSetPtr nodes,
							 xmlOutputBufferPtr buffer);

static const struct _xmlSecTransformKlass xmlSecC14NInclusiveTransformId = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    sizeof(xmlSecTransform),		/* size_t objSize */

    xmlSecNameC14N,
    xmlSecTransformTypeC14N,		/* xmlSecTransformType type; */
    xmlSecTransformUsageC14NMethod | xmlSecTransformUsageDSigTransform,		/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefC14N, 			/* const xmlChar href; */

    xmlSecC14NTransformInitialize, 	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecC14NTransformFinalize,	/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecC14NTransformReadNode,	/* xmlSecTransformReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */

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
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    sizeof(xmlSecTransform),		/* size_t objSize */

    /* same as xmlSecTransformId */    
    xmlSecNameC14NWithComments,
    xmlSecTransformTypeC14N,		/* xmlSecTransformType type; */
    xmlSecTransformUsageC14NMethod | xmlSecTransformUsageDSigTransform,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefC14NWithComments, 	/* const xmlChar href; */

    xmlSecC14NTransformInitialize, 	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecC14NTransformFinalize,	/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecC14NTransformReadNode,	/* xmlSecTransformReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */

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
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    sizeof(xmlSecTransform),		/* size_t objSize */

    xmlSecNameExcC14N,			/* const xmlChar* name; */
    xmlSecTransformTypeC14N,		/* xmlSecTransformType type; */
    xmlSecTransformUsageC14NMethod | xmlSecTransformUsageDSigTransform,	/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefExcC14N,			/* const xmlChar href; */

    xmlSecC14NTransformInitialize, 	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecC14NTransformFinalize,	/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecC14NTransformReadNode,	/* xmlSecTransformReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */
    
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
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),	/* size_t klassSize */
    sizeof(xmlSecTransform),		/* size_t objSize */

    xmlSecNameExcC14NWithComments,
    xmlSecTransformTypeC14N,		/* xmlSecTransformType type; */
    xmlSecTransformUsageC14NMethod | xmlSecTransformUsageDSigTransform,		/* xmlSecAlgorithmUsage usage; */
    xmlSecHrefExcC14NWithComments,	/* const xmlChar href; */

    xmlSecC14NTransformInitialize, 	/* xmlSecTransformInitializeMethod initialize; */
    xmlSecC14NTransformFinalize,	/* xmlSecTransformFinalizeMethod finalize; */
    xmlSecC14NTransformReadNode,	/* xmlSecTransformReadMethod read; */
    NULL,				/* xmlSecTransformSetKeyReqMethod setKeyReq; */
    NULL,				/* xmlSecTransformSetKeyMethod setKey; */
    NULL,				/* xmlSecTransformValidateMethod validate; */
    NULL,				/* xmlSecTransformExecuteMethod execute; */

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

#define xmlSecC14NTransformCheckId(transform) \
    (xmlSecTransformCheckId((transform), xmlSecC14NInclusive) || \
     xmlSecTransformCheckId((transform), xmlSecC14NInclusiveWithComments) || \
     xmlSecTransformCheckId((transform), xmlSecC14NExclusive) || \
     xmlSecTransformCheckId((transform), xmlSecC14NExclusiveWithComments))

/**
 * xmlSecC14NTransformInitialize:
 */
static int
xmlSecC14NTransformInitialize(xmlSecTransformPtr transform) {
    xmlSecAssert2(xmlSecC14NTransformCheckId(transform), -1);

    transform->reserved0 = transform->reserved3 = NULL;
    return(0);
}

/** 
 * xmlSecC14NTransformFinalize
 */
static void
xmlSecC14NTransformFinalize(xmlSecTransformPtr transform) {
    xmlSecAssert(xmlSecC14NTransformCheckId(transform));

    if(transform->reserved0 != NULL) {
	xmlFree(transform->reserved0);
    }        
    if(transform->reserved3 != NULL) {
	xmlFree(transform->reserved3);
    }
    transform->reserved0 = transform->reserved3 = NULL;
}

/** 
 * xmlSecC14NTransformReadNode:
 */
static int
xmlSecC14NTransformReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    xmlNodePtr node;
    xmlChar *buffer;
    xmlChar *p;
    size_t count, len;
    xmlChar **nsList;        
    
    xmlSecAssert2(xmlSecC14NTransformCheckId(transform), -1);

    if(transform->reserved0 != NULL) {	
	xmlFree(transform->reserved0); 
	transform->reserved0 = NULL;
    }
    if(transform->reserved3 != NULL) {
	xmlFree(transform->reserved3);
	transform->reserved3 = NULL;
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
    
    transform->reserved0 = buffer = xmlGetProp(node, BAD_CAST "PrefixList");
    if(buffer == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "PrefixList",
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
    
    transform->reserved3 = nsList = (xmlChar**)xmlMalloc(sizeof(xmlChar*) * (count + 2));
    if(transform->reserved3 == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlMalloc",
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
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_TRANSFORM,
		    "xmlSecC14NInclusive, xmlSecC14NInclusiveWithComments, xmlSecC14NExclusive, xmlSecC14NExclusiveWithComments");    
	return(-1);
    }
    
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlC14NExecute",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
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
		    xmlSecNodeGetName(transformNode),
		    "xmlSecFindChild",
		    XMLSEC_ERRORS_R_NODE_ALREADY_PRESENT,
		    "<dsig:InclusiveNamespaces>");
	return(-1);
    }
    
    node = xmlSecAddChild(transformNode, BAD_CAST "InclusiveNamespaces", xmlExcC14NNs);
    if(node == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    xmlSecNodeGetName(transformNode),
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "<dsig:InclusiveNamespaces>");
	return(-1);
    }    
    
    xmlSetProp(node, BAD_CAST "PrefixList", prefixList);    
    return(0);
}


