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

static const xmlChar xmlExcC14NNs[] = "http://www.w3.org/2001/10/xml-exc-c14n#";
static const xmlChar xmlExcC14NWithCommentsNs[] = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";


static xmlSecTransformPtr xmlSecC14NTransformCreate	(xmlSecTransformId id);
static void		xmlSecC14NTransformDestroy	(xmlSecTransformPtr transform);
static int 		xmlSecC14NTransformReadNode	(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);
static int 		xmlSecC14NTransformExec		(xmlSecC14NTransformPtr transform,
							 xmlDocPtr doc,
							 xmlNodeSetPtr nodes,
							 xmlOutputBufferPtr buffer);

static const struct _xmlSecC14NTransformId xmlSecC14NInclusiveTransformId = {
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

static const struct _xmlSecC14NTransformId xmlSecC14NInclusiveWithCommentsTransformId = {
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

static const struct _xmlSecC14NTransformId xmlSecC14NExclusiveTransformId = {
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

static const struct _xmlSecC14NTransformId xmlSecC14NExclusiveWithCommentsTransformId = {
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
 * @id:
 *
 * Creates new c14n trasnform
 */
static xmlSecTransformPtr 
xmlSecC14NTransformCreate(xmlSecTransformId id) {
    static const char func[] ATTRIBUTE_UNUSED = "";
    xmlSecC14NTransformPtr transform;
    
    if((id != xmlSecC14NInclusive) && (id != xmlSecC14NInclusiveWithComments) &&
       (id != xmlSecC14NExclusive) && (id != xmlSecC14NExclusiveWithComments)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: id is unknown\n",
	    func);
#endif 	    
	return(NULL);
    }
    
    transform = (xmlSecC14NTransformPtr) xmlMalloc(sizeof(xmlSecC14NTransform));  
    if (transform == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: malloc failed\n",
	    func);
#endif 	    
	return(NULL);
    }
    memset(transform, 0, sizeof(xmlSecC14NTransform));

    transform->id = (xmlSecC14NTransformId)id;
    return((xmlSecTransformPtr)transform);
}

/** 
 * xmlSecC14NTransformDestroy
 * @transform
 * 
 *
 */
static void
xmlSecC14NTransformDestroy(xmlSecTransformPtr transform) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecC14NTransformDestroy";
    xmlSecC14NTransformPtr ptr;

    if(!xmlSecTransformCheckId(transform, xmlSecC14NInclusive) &&
       !xmlSecTransformCheckId(transform, xmlSecC14NInclusiveWithComments) &&
       !xmlSecTransformCheckId(transform, xmlSecC14NExclusive) &&
       !xmlSecTransformCheckId(transform, xmlSecC14NExclusiveWithComments) ) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
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
 *
 *
 *
 */
static int
xmlSecC14NTransformReadNode(xmlSecTransformPtr transform, xmlNodePtr transformNode) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecC14NTransformReadNode";
    xmlSecC14NTransformPtr ptr;
    xmlNodePtr node;
    xmlChar *buffer;
    xmlChar *p;
    size_t count, len;
    xmlChar **nsList;        
    
    if(!xmlSecTransformCheckId(transform, xmlSecC14NInclusive) &&
       !xmlSecTransformCheckId(transform, xmlSecC14NInclusiveWithComments) &&
       !xmlSecTransformCheckId(transform, xmlSecC14NExclusive) &&
       !xmlSecTransformCheckId(transform, xmlSecC14NExclusiveWithComments) ) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
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
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: InclusiveNamespaces node has no PrefixList att\n",
	    func);	
#endif 	    
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
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "xmlSecC14NTransformInclusivePrefixesListRead: malloc failed\n");
#endif 	    
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
 *
 */
int		
xmlSecC14NExclAddInclNamespaces(xmlNodePtr transformNode, const xmlChar *prefixList) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecC14NExclAddInclNamespaces";
    xmlNodePtr node;
    
    if((transformNode == NULL) || (prefixList == NULL)) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transformNode or prefix list is null\n",
	    func);	
#endif 	    
	return(-1);
    }

    node = xmlSecFindChild(transformNode, BAD_CAST "InclusiveNamespaces", xmlExcC14NNs);
    if(node != NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: InclusiveNamespaces node already present\n",
	    func);	
#endif 	    
	return(-1);
    }
    
    node = xmlSecAddChild(transformNode, BAD_CAST "InclusiveNamespaces", xmlExcC14NNs);
    if(node == NULL) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: failed to create InclusiveNamespaces node\n",
	    func);	
#endif 	    
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
			xmlNodeSetPtr nodes, xmlOutputBufferPtr buffer) {
    static const char func[] ATTRIBUTE_UNUSED = "xmlSecC14NTransformExec";
    int ret;
        
    if(xmlSecTransformCheckId(transform, xmlSecC14NInclusive)) {    
    	ret = xmlC14NDocSaveTo(doc, nodes, 0, NULL, 0, buffer);
    } else if(xmlSecTransformCheckId(transform, xmlSecC14NInclusiveWithComments)) {
	 ret = xmlC14NDocSaveTo(doc, nodes, 0, NULL, 1, buffer); 
    } else if(xmlSecTransformCheckId(transform, xmlSecC14NExclusive)) {
	ret = xmlC14NDocSaveTo(doc, nodes, 1, (xmlChar**)(transform->c14nData), 0, buffer);
    } else if(xmlSecTransformCheckId(transform, xmlSecC14NExclusiveWithComments)) {
	ret = xmlC14NDocSaveTo(doc, nodes, 1, (xmlChar**)(transform->c14nData), 1, buffer);
    } else if(transform == NULL) {
	/* the default c14n trasnform */
    	ret = xmlC14NDocSaveTo(doc, nodes, 0, NULL, 0, buffer);	
    } else {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform is invalid\n",
	    func);	
#endif 	    
	return(-1);    
    }

    if(ret < 0) {
#ifdef XMLSEC_DEBUG
        xmlGenericError(xmlGenericErrorContext,
	    "%s: transform failed\n",
	    func);	
#endif 	    
	return(-1);
    }    
    return(0);
}










