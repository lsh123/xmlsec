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
static int 		xmlSecC14NTransformExec		(xmlSecC14NTransformPtr transform,
							 xmlDocPtr doc,
							 xmlSecNodeSetPtr nodes,
							 xmlOutputBufferPtr buffer);

static const struct _xmlSecC14NTransformIdStruct xmlSecC14NInclusiveTransformId = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeC14N,		/* xmlSecTransformType type; */
    xmlSecUsageDSigC14N | xmlSecUsageDSigTransform,		/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/TR/2001/REC-xml-c14n-20010315", /* const xmlChar href; */

    xmlSecC14NTransformCreate, 		/* xmlSecTransformCreateMethod create; */
    xmlSecC14NTransformDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecC14NTransformReadNode,	/* xmlSecTransformReadMethod read; */
    
    /* c14n methods */
    xmlSecC14NTransformExec		/* xmlSecC14NTransformExecuteMethod executeC14N; */
};
xmlSecTransformId xmlSecC14NInclusive = (xmlSecTransformId)&xmlSecC14NInclusiveTransformId;

static const struct _xmlSecC14NTransformIdStruct xmlSecC14NInclusiveWithCommentsTransformId = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeC14N,		/* xmlSecTransformType type; */
    xmlSecUsageDSigC14N | xmlSecUsageDSigTransform,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments", /* const xmlChar href; */

    xmlSecC14NTransformCreate, 		/* xmlSecTransformCreateMethod create; */
    xmlSecC14NTransformDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecC14NTransformReadNode,	/* xmlSecTransformReadMethod read; */
    
    /* c14n methods */
    xmlSecC14NTransformExec		/* xmlSecC14NTransformExecuteMethod executeC14N; */
};
xmlSecTransformId xmlSecC14NInclusiveWithComments = (xmlSecTransformId)&xmlSecC14NInclusiveWithCommentsTransformId;

static const struct _xmlSecC14NTransformIdStruct xmlSecC14NExclusiveTransformId = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeC14N,		/* xmlSecTransformType type; */
    xmlSecUsageDSigC14N | xmlSecUsageDSigTransform,	/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/10/xml-exc-c14n#", /* const xmlChar href; */

    xmlSecC14NTransformCreate, 		/* xmlSecTransformCreateMethod create; */
    xmlSecC14NTransformDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecC14NTransformReadNode,	/* xmlSecTransformReadMethod read; */
    
    /* c14n methods */
    xmlSecC14NTransformExec		/* xmlSecC14NTransformExecuteMethod executeC14N; */
};
xmlSecTransformId xmlSecC14NExclusive = (xmlSecTransformId)&xmlSecC14NExclusiveTransformId;

static const struct _xmlSecC14NTransformIdStruct xmlSecC14NExclusiveWithCommentsTransformId = {
    /* same as xmlSecTransformId */    
    xmlSecTransformTypeC14N,		/* xmlSecTransformType type; */
    xmlSecUsageDSigC14N | xmlSecUsageDSigTransform,		/* xmlSecAlgorithmUsage usage; */
    BAD_CAST "http://www.w3.org/2001/10/xml-exc-c14n#WithComments", /* const xmlChar href; */

    xmlSecC14NTransformCreate, 		/* xmlSecTransformCreateMethod create; */
    xmlSecC14NTransformDestroy,		/* xmlSecTransformDestroyMethod destroy; */
    xmlSecC14NTransformReadNode,	/* xmlSecTransformReadMethod read; */
    
    /* c14n methods */
    xmlSecC14NTransformExec		/* xmlSecC14NTransformExecuteMethod executeC14N; */
};
xmlSecTransformId xmlSecC14NExclusiveWithComments = (xmlSecTransformId)&xmlSecC14NExclusiveWithCommentsTransformId;

/**
 * xmlSecC14NTransformCreate:
 * @id: the c14n transform id
 *
 * Creates new c14n trasnform.
 *
 * Returns created transform or NULL of an error occurs.
 */
static xmlSecTransformPtr 
xmlSecC14NTransformCreate(xmlSecTransformId id) {
    xmlSecC14NTransformPtr transform;

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
    
    transform = (xmlSecC14NTransformPtr) xmlMalloc(sizeof(xmlSecC14NTransform));  
    if (transform == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    NULL);
	return(NULL);
    }
    memset(transform, 0, sizeof(xmlSecC14NTransform));

    transform->id = (xmlSecC14NTransformId)id;
    return((xmlSecTransformPtr)transform);
}

/** 
 * xmlSecC14NTransformDestroy
 * @transform: the C14N transform
 * 
 * Destroys the C14N transform.
 */
static void
xmlSecC14NTransformDestroy(xmlSecTransformPtr transform) {
    xmlSecC14NTransformPtr ptr;

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

    ptr = (xmlSecC14NTransformPtr)transform;    
    if(ptr->data != NULL) {
	xmlFree(ptr->data);
    }    
    
    if(ptr->c14nData != NULL) {
	xmlFree(ptr->c14nData);
    }
    
    memset(ptr, 0, sizeof(xmlSecC14NTransform));
    xmlFree(ptr);    
}

/** 
 * xmlSecC14NTransformReadNode
 * @transform: the C14N transform 
 * @transformNode: the transform node
 *
 * Reads C14N transform node.
 *
 * Returns 0 if success or a negative values if an error occurs.
 */
static int
xmlSecC14NTransformReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    xmlSecC14NTransformPtr ptr;
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

    ptr = (xmlSecC14NTransformPtr)transform;
    if(ptr->data != NULL) {	
	xmlFree(ptr->data); 
	ptr->data = NULL;
    }
    if(ptr->c14nData != NULL) {
	xmlFree(ptr->c14nData);
	ptr->c14nData = NULL;
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
    
    ptr->data = buffer = xmlGetProp(node, BAD_CAST "PrefixList");
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
    
    ptr->c14nData = nsList = (xmlChar**)xmlMalloc(sizeof(xmlChar*) * (count + 2));
    if(ptr->c14nData == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE, 
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    NULL);
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
 * xmlSecC14NExclAddInclNamespaces:
 * @transformNode: 	the exclusive c14n transform node
 * @prefixList: 	the white space delimited  list of namespace prefixes, 
 *			where "#default" indicates the default namespace
 *
 * Adds "inclusive" namespaces to the ExcC14N transform node
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

/** 
 * xmlSecC14NTransformExec
 * @transform: 
 * @doc:
 * @nodes:
 * @buffer:
 *
 * Does the c14n on the input document/node set and writes the result
 * into the buffer
 */
static int
xmlSecC14NTransformExec(xmlSecC14NTransformPtr transform, xmlDocPtr doc,
			xmlSecNodeSetPtr nodes, xmlOutputBufferPtr buffer) {
    int ret;


    xmlSecAssert2(doc!= NULL, -1);
    xmlSecAssert2(buffer != NULL, -1);

    if(transform == NULL) {
	/* the default c14n trasnform */
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
			1, (xmlChar**)(transform->c14nData), 0, buffer);
    } else if(xmlSecTransformCheckId(transform, xmlSecC14NExclusiveWithComments)) {
	ret = xmlC14NExecute(doc, 
			(xmlC14NIsVisibleCallback)xmlSecNodeSetContains, 
			nodes, 
			1, (xmlChar**)(transform->c14nData), 1, buffer);
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

