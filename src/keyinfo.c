/** 
 * XMLSec library
 *
 * XMLDsig:KeyInfo node processing
 * http://www.w3.org/TR/xmlSec-core/#sec-KeyInfo
 *
 * The KeyInfo Element
 *
 * KeyInfo is an optional element that enables the recipient(s) to obtain 
 * the key needed to validate the signature.  KeyInfo may contain keys, 
 * names, certificates and other public key management information, such as 
 * in-band key distribution or key agreement data. 
 * 
 *  Schema Definition:
 *
 *  <element name="KeyInfo" type="ds:KeyInfoType"/> 
 *  <complexType name="KeyInfoType" mixed="true">
 *    <choice maxOccurs="unbounded"> 
 *       <element ref="ds:KeyName"/> 
 *       <element ref="ds:KeyValue"/> 
 *       <element ref="ds:RetrievalMethod"/> 
 *       <element ref="ds:X509Data"/> 
 *       <element ref="ds:PGPData"/> 
 *       <element ref="ds:SPKIData"/>
 *       <element ref="ds:MgmtData"/>
 *       <any processContents="lax" namespace="##other"/>
 *       <!-- (1,1) elements from (0,unbounded) namespaces -->
 *    </choice>
 *    <attribute name="Id" type="ID" use="optional"/>
 *  </complexType>
 *    
 * DTD:
 *    
 * <!ELEMENT KeyInfo (#PCDATA|KeyName|KeyValue|RetrievalMethod|
 *                    X509Data|PGPData|SPKIData|MgmtData %KeyInfo.ANY;)* >      
 * <!ATTLIST KeyInfo  Id  ID   #IMPLIED >
 *  
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>
 
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/errors.h>


/**************************************************************************
 *
 * Hi level functions
 *
 *************************************************************************/
/**
 * xmlSecKeyInfoNodeRead:
 * @keyInfoNode: the pointer to <dsig:KeyInfo> node.
 * @keyInfoCtx: the pointer to #xmlSecKeyInfoCtx structure.
 *
 * Parses the <dsig:KeyInfo> element and extracts the key (with required 
 * id, type and usage).
 *
 * Returns 0 on success or -1 if an error occurs.
 */
int
xmlSecKeyInfoNodeRead(xmlNodePtr keyInfoNode, xmlSecKeyPtr key, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    const xmlChar* nodeName;
    const xmlChar* nodeNs;
    xmlSecKeyDataId dataId;
    xmlNodePtr cur;
    int ret;
    
    xmlSecAssert2(keyInfoNode != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    for(cur = xmlSecGetNextElementNode(keyInfoNode->children); 
	cur != NULL;
	cur = xmlSecGetNextElementNode(cur->next)) {
    
	/* find data id */
	nodeName = cur->name;
	nodeNs = xmlSecGetNodeNsHref(cur);
	dataId = xmlSecKeyDataIdsFindByNode(nodeName, nodeNs, xmlSecKeyDataUsageKeyInfoNodeRead);
	if(dataId == xmlSecKeyDataIdUnknown) {
	    /* todo: laxi schema validation */
	    if(0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlSecKeyDataIdsFindByNode",
			    XMLSEC_ERRORS_R_INVALID_NODE,
			    "name=\"%s\", href=\"%s\"", 
			    nodeName, 
			    (nodeNs) ? nodeNs : BAD_CAST "");
		return(-1);
	    }
	    continue;
	}
	/* todo: allowed origins? */
	
	/* read data node */
	ret = xmlSecKeyDataXmlRead(dataId, key, cur, keyInfoCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecKeyDataKlassGetName(dataId),
			"xmlSecKeyDataXmlRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"name=\"%s\", href=\"%s\"", 
			nodeName, 
			(nodeNs) ? nodeNs : BAD_CAST "");
	    return(-1);
	}
    }
    
    return(0);    
}

/**
 * xmlSecKeyInfoNodeWrite:
 * @keyInfoNode: the pointer to <dsig:KeyInfo> node.
 * @key: the key.
 * @keyInfoCtx: the pointer to #xmlSecKeyInfoCtx structure.
 *
 * Writes the key into the <dsig:KeyInfo> template @keyInfoNode.
 *
 * Returns 0 on success or -1 if an error occurs.
 */
int 
xmlSecKeyInfoNodeWrite(xmlNodePtr keyInfoNode, xmlSecKeyPtr key, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    const xmlChar* nodeName;
    const xmlChar* nodeNs;
    xmlSecKeyDataId dataId;
    xmlNodePtr cur;
    int ret;
    
    xmlSecAssert2(keyInfoNode != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    for(cur = xmlSecGetNextElementNode(keyInfoNode->children); 
	cur != NULL;
	cur = xmlSecGetNextElementNode(cur->next)) {
    
	/* find data id */
	nodeName = cur->name;
	nodeNs = xmlSecGetNodeNsHref(cur);
	dataId = xmlSecKeyDataIdsFindByNode(nodeName, nodeNs, xmlSecKeyDataUsageKeyInfoNodeWrite);
	if(dataId == xmlSecKeyDataIdUnknown) {
	    /* todo: laxi schema validation */
	    if(0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    NULL,
			    "xmlSecKeyDataIdsFindByNode",
			    XMLSEC_ERRORS_R_INVALID_NODE,
			    "name=\"%s\", href=\"%s\"", 
			    nodeName, 
			    (nodeNs) ? nodeNs : BAD_CAST "");
		return(-1);
	    }
	    continue;
	}

	ret = xmlSecKeyDataXmlWrite(dataId, key, cur, keyInfoCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecKeyDataKlassGetName(dataId),
			"xmlSecKeyDataXmlWrite",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"xmlSecKeyDataXmlWrite(name=\"%s\", href=\"%s\")", 
			nodeName, 
			(nodeNs) ? nodeNs : BAD_CAST "");
	    return(-1);
	}
    }
    
    return(0);
} 



/**************************************************************************
 *
 * <dsig:KeyName> processing
 *
 *************************************************************************/
static int			xmlSecKeyDataNameXmlRead	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int			xmlSecKeyDataNameXmlWrite	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyDataKlass xmlSecKeyDataNameKlass = {
    sizeof(xmlSecKeyDataKlass),
    sizeof(xmlSecKeyData),

    /* data */
    "KeyName",
    xmlSecKeyDataUsageKeyInfoNode, 		/* xmlSecKeyDataUsage usage; */
    NULL,					/* const xmlChar* href; */
    BAD_CAST "KeyName",				/* const xmlChar* dataNodeName; */
    xmlSecDSigNs,				/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    NULL,					/* xmlSecKeyDataInitializeMethod initialize; */
    NULL,					/* xmlSecKeyDataDuplicateMethod duplicate; */
    NULL,					/* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,					/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    NULL,					/* xmlSecKeyDataGetTypeMethod getType; */
    NULL,					/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */    

    /* read/write */
    xmlSecKeyDataNameXmlRead,			/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecKeyDataNameXmlWrite,   		/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,					/* xmlSecKeyDataBinReadMethod binRead; */
    NULL,					/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    NULL,					/* xmlSecKeyDataDebugDumpMethod debugDump; */
    NULL,					/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */
};

xmlSecKeyDataId 
xmlSecKeyDataNameGetKlass(void) {
    return(&xmlSecKeyDataNameKlass);
}

static int 
xmlSecKeyDataNameXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    const xmlChar* oldName;
    xmlChar* newName;
    int ret;

    xmlSecAssert2(id == xmlSecKeyDataNameId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    oldName = xmlSecKeyGetName(key);
    newName = xmlNodeGetContent(node);
    if(newName == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    "xmlNodeGetContent",
		    XMLSEC_ERRORS_R_INVALID_NODE_CONTENT,
		    "<dsig:KeyName>");    
	return(-1);
    }
    /* TODO: do we need to decode the name? */
    
    /* compare name values */
    if((oldName != NULL) && !xmlStrEqual(oldName, newName)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_KEY_DATA,
		    "KeyName is already specified");    
	xmlFree(newName);
	return(-1);
    }

    /* try to find key in the manager */
    if((xmlSecKeyGetValue(key) == NULL) && (keyInfoCtx->keysMngr != NULL)) {
	ret = xmlSecKeysMngrFindKey(keyInfoCtx->keysMngr, key, newName, keyInfoCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecKeyDataKlassGetName(id),
			"xmlSecKeysMngrFindKey",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE); 
	    xmlFree(newName);
	    return(-1);
	}
    }		
    
    /* finally set key name if it is not there */
    if(xmlSecKeyGetName(key) == NULL) {
	xmlSecKeySetName(key, newName);
    }
    xmlFree(newName);
    return(0);
}

static int 
xmlSecKeyDataNameXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    const xmlChar* name;

    xmlSecAssert2(id == xmlSecKeyDataNameId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    name = xmlSecKeyGetName(key);
    if(name != NULL) {
	/* TODO: encode the key name */
	xmlNodeSetContent(node, name);
    }
    return(0);
}

/**************************************************************************
 *
 * <dsig:KeyValue> processing
 *
 *
 * http://www.w3.org/TR/xmldsig-core/#sec-KeyValue
 *
 * The KeyValue element contains a single public key that may be useful in 
 * validating the signature. Structured formats for defining DSA (REQUIRED) 
 * and RSA (RECOMMENDED) public keys are defined in Signature Algorithms 
 * (section 6.4). The KeyValue element may include externally defined 
 * public keys values represented as PCDATA or element types from an external 
 * namespace.
 *
 * Schema Definition:
 *
 * <element name="KeyValue" type="ds:KeyValueType"/> 
 *   <complexType name="KeyValueType" mixed="true">
 *     <choice>
 *       <element ref="ds:DSAKeyValue"/>
 *       <element ref="ds:RSAKeyValue"/>
 *       <any namespace="##other" processContents="lax"/>
 *     </choice>
 *   </complexType>
 *    
 * DTD:
 *  
 * <!ELEMENT KeyValue (#PCDATA|DSAKeyValue|RSAKeyValue %KeyValue.ANY;)* >
 *
 *************************************************************************/
static int			xmlSecKeyDataValueXmlRead	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int			xmlSecKeyDataValueXmlWrite	(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyDataKlass xmlSecKeyDataValueKlass = {
    sizeof(xmlSecKeyDataKlass),
    sizeof(xmlSecKeyData),

    /* data */
    "KeyValue",
    xmlSecKeyDataUsageKeyInfoNode, 		/* xmlSecKeyDataUsage usage; */
    NULL,					/* const xmlChar* href; */
    BAD_CAST "KeyValue",			/* const xmlChar* dataNodeName; */
    xmlSecDSigNs,				/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    NULL,					/* xmlSecKeyDataInitializeMethod initialize; */
    NULL,					/* xmlSecKeyDataDuplicateMethod duplicate; */
    NULL,					/* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,					/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    NULL,					/* xmlSecKeyDataGetTypeMethod getType; */
    NULL,					/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */    

    /* read/write */
    xmlSecKeyDataValueXmlRead,			/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecKeyDataValueXmlWrite, 	  	/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,					/* xmlSecKeyDataBinReadMethod binRead; */
    NULL,					/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    NULL,					/* xmlSecKeyDataDebugDumpMethod debugDump; */
    NULL,					/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */
};

xmlSecKeyDataId 
xmlSecKeyDataValueGetKlass(void) {
    return(&xmlSecKeyDataValueKlass);
}

static int 
xmlSecKeyDataValueXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    const xmlChar* nodeName;
    const xmlChar* nodeNs;
    xmlSecKeyDataId dataId;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(id == xmlSecKeyDataValueId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    cur = xmlSecGetNextElementNode(node->children);
    if(cur == NULL) {
	/* just an empty node */
	return(0);
    }

    /* find data id */
    nodeName = cur->name;
    nodeNs = xmlSecGetNodeNsHref(cur);
    dataId = xmlSecKeyDataIdsFindByNode(nodeName, nodeNs, xmlSecKeyDataUsageKeyValueNodeRead);
    if(dataId != xmlSecKeyDataIdUnknown) {
	/* read data node */
	ret = xmlSecKeyDataXmlRead(dataId, key, cur, keyInfoCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecKeyDataKlassGetName(id),
			"xmlSecKeyDataXmlRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"name=\"%s\", href=\"%s\"", 
			nodeName, 
			(nodeNs) ? nodeNs : BAD_CAST "");
	    return(-1);
	}
    } else if(0) {
	/* todo: laxi schema validation */
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    "xmlSecKeyDataIdsFindByNode",
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "name=\"%s\", href=\"%s\"", 
		    nodeName, 
		    (nodeNs) ? nodeNs : BAD_CAST "");
	return(-1);	
    }

    /* <dsig:KeyValue> might have only one node */
    cur = xmlSecGetNextElementNode(cur->next);  
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    "xmlSecGetNextElementNode",
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "%s", (cur->name != NULL) ? (char*)cur->name : "NULL");
	return(-1);
    }
    
    return(0);
}

static int 
xmlSecKeyDataValueXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    const xmlChar* nodeName;
    const xmlChar* nodeNs;  
    xmlNodePtr cur;
    int ret;
    
    xmlSecAssert2(id == xmlSecKeyDataValueId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(!xmlSecKeyDataIsValid(key->value) || !xmlSecKeyDataCheckUsage(key->value, xmlSecKeyDataUsageKeyValueNodeWrite)){
	/* nothing to write */
	return(0);
    }

    nodeName = key->value->id->dataNodeName;
    nodeNs = key->value->id->dataNodeNs;
    xmlSecAssert2(nodeName != NULL, -1);
    
    /* remove all existing key value */
    xmlNodeSetContent(node, NULL);
    
    /* create key node */
    cur = xmlSecAddChild(node, nodeName, nodeNs);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    "xmlSecAddChild",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "name=\"%s\"", nodeName);    
	return(-1);	
    }

    ret = xmlSecKeyDataXmlWrite(key->value->id, key, cur, keyInfoCtx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    "xmlSecKeyDataXmlWrite",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "name=\"%s\"", nodeName);    
	return(-1);	
    }
    return(0);
}

/**************************************************************************
 *
 * <dsig:RetrievalMethod> processing
 *
 *************************************************************************/
static int			xmlSecKeyDataRetrievalMethodXmlRead(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int			xmlSecKeyDataRetrievalMethodXmlWrite(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);



static xmlSecKeyDataKlass xmlSecKeyDataRetrievalMethodKlass = {
    sizeof(xmlSecKeyDataKlass),
    sizeof(xmlSecKeyData),

    /* data */
    xmlSecNameRetrievalMethod,
    xmlSecKeyDataUsageKeyInfoNode, 		/* xmlSecKeyDataUsage usage; */
    NULL,					/* const xmlChar* href; */
    xmlSecNodeRetrievalMethod,			/* const xmlChar* dataNodeName; */
    xmlSecDSigNs,				/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    NULL,					/* xmlSecKeyDataInitializeMethod initialize; */
    NULL,					/* xmlSecKeyDataDuplicateMethod duplicate; */
    NULL,					/* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,					/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    NULL,					/* xmlSecKeyDataGetTypeMethod getType; */
    NULL,					/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */    

    /* read/write */
    xmlSecKeyDataRetrievalMethodXmlRead,	/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecKeyDataRetrievalMethodXmlWrite,   	/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,					/* xmlSecKeyDataBinReadMethod binRead; */
    NULL,					/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    NULL,					/* xmlSecKeyDataDebugDumpMethod debugDump; */
    NULL,					/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */
};

static int			xmlSecKeyDataRetrievalMethodReadXmlResult(xmlSecKeyDataId typeId,
								 xmlSecKeyPtr key,
								 const xmlChar* buffer,
								 size_t bufferSize,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);

xmlSecKeyDataId 
xmlSecKeyDataRetrievalMethodGetKlass(void) {
    return(&xmlSecKeyDataRetrievalMethodKlass);
}

static int 
xmlSecKeyDataRetrievalMethodXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlNodePtr cur;
    xmlSecTransformStatePtr state = NULL;
    xmlSecKeyDataId dataId = xmlSecKeyDataIdUnknown;
    xmlChar *retrType = NULL;
    xmlChar *uri = NULL;
    int res = -1;
    int ret;
    
    xmlSecAssert2(id == xmlSecKeyDataRetrievalMethodId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* read attributes first */
    uri = xmlGetProp(node, BAD_CAST "URI");
    if((uri == NULL) || (xmlStrlen(uri) == 0) || (uri[0] == '#')) {
	/* same document uri */
	if(!xmlSecKeyInfoNodeCheckOrigin(keyInfoCtx, xmlSecKeyOriginRetrievalDocument)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecKeyDataKlassGetName(id),
			"xmlSecKeyInfoNodeCheckOrigin",
			XMLSEC_ERRORS_R_INVALID_KEY_ORIGIN,
			"xmlSecKeyOriginRetrievalDocument");
	    res = 0;
	    goto done;
	}
    } else {
	/* remote document */
	if(!xmlSecKeyInfoNodeCheckOrigin(keyInfoCtx, xmlSecKeyOriginRetrievalRemote)) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecKeyDataKlassGetName(id),
			"xmlSecKeyInfoNodeCheckOrigin",
			XMLSEC_ERRORS_R_INVALID_KEY_ORIGIN,
			"xmlSecKeyOriginRetrievalRemote");
	    res = 0;
	    goto done;
	}
    }
    if(!xmlSecKeyInfoNodeCheckRetrievalsLevel(keyInfoCtx)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    "xmlSecKeyInfoNodeCheckRetrievalsLevel",
		    XMLSEC_ERRORS_R_MAX_RETRIEVALS_LEVEL,
		    "%d", keyInfoCtx->retrievalsLevel);
	goto done;
    }
    ++keyInfoCtx->retrievalsLevel;

    state = xmlSecTransformStateCreate(node->doc, NULL, (char*)uri);
    if(state == NULL){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    "xmlSecTransformStateCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }	

    /* read possible trasnforms */
    cur = xmlSecGetNextElementNode(node->children);
    if((cur != NULL) && xmlSecCheckNodeName(cur, BAD_CAST "Transforms", xmlSecDSigNs)) {
	ret = xmlSecTransformsNodeRead(state, cur);
	if(ret < 0){
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecKeyDataKlassGetName(id),
			"xmlSecTransformsNodeRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    goto done;
	}	
	cur = xmlSecGetNextElementNode(cur->next);
    }
    if(cur != NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    xmlSecNodeGetName(cur),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    /* finally get transforms results */
    ret = xmlSecTransformStateFinal(state, xmlSecTransformResultBinary);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    "xmlSecTransformStateFinal",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }

    retrType = xmlGetProp(node, BAD_CAST "Type");
    if(retrType != NULL) {
	dataId = xmlSecKeyDataIdsFindByHref(retrType, xmlSecKeyDataUsageRetrievalMethodNode);
    }

    /* todo: option to abort if type is unknown */
    if((dataId == xmlSecKeyDataIdUnknown) && (0)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    NULL,
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "unknown or unspecified type \"%s\"", 
		    (retrType != NULL) ? retrType : BAD_CAST "NULL");
	goto done;
    }

    /* assume that the data is in XML if we could not find id */    
    if((dataId == xmlSecKeyDataIdUnknown) || 
       ((dataId->usage & xmlSecKeyDataUsageRetrievalMethodNodeXml) != 0)) {

	ret = xmlSecKeyDataRetrievalMethodReadXmlResult(dataId, key,
				    xmlSecBufferGetData(state->curBuf),
                            	    xmlSecBufferGetSize(state->curBuf),
				    keyInfoCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecKeyDataKlassGetName(id),
			"xmlSecKeyDataRetrievalMethodReadXmlResult",
	    		XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    goto done;
	}    
    } else {
	ret = xmlSecKeyDataBinRead(dataId, key, 
				    xmlSecBufferGetData(state->curBuf),
                            	    xmlSecBufferGetSize(state->curBuf),
				    keyInfoCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecKeyDataKlassGetName(id),
			"xmlSecKeyDataBinRead",
	    		XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    goto done;
	}    
    }
    
    res = 0;    
done:
    if(state != NULL) {
	xmlSecTransformStateDestroy(state);
    }
    if(uri != NULL) {
	xmlFree(uri);
    }
    if(retrType != NULL) {
	xmlFree(retrType);
    }
    return(res);
}

static int 
xmlSecKeyDataRetrievalMethodXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(id == xmlSecKeyDataRetrievalMethodId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* just do nothing */
    return(0);
}

static int
xmlSecKeyDataRetrievalMethodReadXmlResult(xmlSecKeyDataId typeId, xmlSecKeyPtr key,
					  const xmlChar* buffer, size_t bufferSize,
					  xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlDocPtr doc;
    xmlNodePtr cur;
    const xmlChar* nodeName;
    const xmlChar* nodeNs;
    xmlSecKeyDataId dataId;
    int ret;
    
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2(bufferSize > 0, -1); 
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    doc = xmlRecoverMemory((const char*)buffer, bufferSize);
    if(doc == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(typeId),
		    "xmlRecoverMemory",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
	
    cur = xmlDocGetRootElement(doc);
    if(cur == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(typeId),
		    "xmlDocGetRootElement",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	xmlFreeDoc(doc);
	return(-1);	
    }

    nodeName = cur->name;
    nodeNs = xmlSecGetNodeNsHref(cur);
    dataId = xmlSecKeyDataIdsFindByNode(nodeName, nodeNs, xmlSecKeyDataUsageRetrievalMethodNodeXml);
    if(dataId == xmlSecKeyDataIdUnknown) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(typeId),
		    "xmlSecKeyDataIdsFindByNode",
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "name=\"%s\", href=\"%s\"", 
		    nodeName, 
		    (nodeNs) ? nodeNs : BAD_CAST "");
	xmlFreeDoc(doc);
	
	/* todo: laxi schema validation */
	return((1) ? 0 : -1);
    } else if((typeId != xmlSecKeyDataIdUnknown) && (typeId != dataId)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(typeId),
		    NULL,
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "expected id \"%s\" does not match the found one \"%s\"", 
		    typeId->name, dataId->name); 
	/* todo: ignore type mismatch */
	if(0) {
	    xmlFreeDoc(doc);
	    return(-1);
	}
    }

    /* read data node */
    ret = xmlSecKeyDataXmlRead(dataId, key, cur, keyInfoCtx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(typeId),
		    "xmlSecKeyDataXmlRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "name=\"%s\", href=\"%s\"", 
		    nodeName, 
		    (nodeNs) ? nodeNs : BAD_CAST "");
	xmlFreeDoc(doc);
	return(-1);
    }
    
    xmlFreeDoc(doc);
    return(0);
}


#ifndef XMLSEC_NO_XMLENC
/**************************************************************************
 *
 * <enc:EncryptedKey> processing
 *
 *************************************************************************/
static int			xmlSecKeyDataEncryptedKeyXmlRead(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int			xmlSecKeyDataEncryptedKeyXmlWrite(xmlSecKeyDataId id,
								 xmlSecKeyPtr key,
								 xmlNodePtr node,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);



static xmlSecKeyDataKlass xmlSecKeyDataEncryptedKeyKlass = {
    sizeof(xmlSecKeyDataKlass),
    sizeof(xmlSecKeyData),

    /* data */
    xmlSecNameEncryptedKey,
    xmlSecKeyDataUsageKeyInfoNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 		
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefEncryptedKey,			/* const xmlChar* href; */
    xmlSecNodeEncryptedKey,			/* const xmlChar* dataNodeName; */
    xmlSecEncNs,				/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    NULL,					/* xmlSecKeyDataInitializeMethod initialize; */
    NULL,					/* xmlSecKeyDataDuplicateMethod duplicate; */
    NULL,					/* xmlSecKeyDataFinalizeMethod finalize; */
    NULL,					/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    NULL,					/* xmlSecKeyDataGetTypeMethod getType; */
    NULL,					/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */    

    /* read/write */
    xmlSecKeyDataEncryptedKeyXmlRead,		/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecKeyDataEncryptedKeyXmlWrite,   	/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    NULL,					/* xmlSecKeyDataBinReadMethod binRead; */
    NULL,					/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    NULL,					/* xmlSecKeyDataDebugDumpMethod debugDump; */
    NULL,					/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */
};

xmlSecKeyDataId 
xmlSecKeyDataEncryptedKeyGetKlass(void) {
    return(&xmlSecKeyDataEncryptedKeyKlass);
}

static int 
xmlSecKeyDataEncryptedKeyXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecEncCtxPtr encCtx = NULL;
    xmlSecEncResultPtr encResult = NULL; 
    int res = -1;
    int ret;

    xmlSecAssert2(id == xmlSecKeyDataEncryptedKeyId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    if(!xmlSecKeyInfoNodeCheckOrigin(keyInfoCtx, xmlSecKeyOriginEncryptedKey) ){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    "xmlSecKeyInfoNodeCheckOrigin",
		    XMLSEC_ERRORS_R_INVALID_KEY_ORIGIN,
		    "xmlSecKeyOriginEncryptedKey");
	return(0);
    }
    
    if(!xmlSecKeyInfoNodeCheckEncKeysLevel(keyInfoCtx)) {
        xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    "xmlSecKeyInfoNodeCheckEncKeysLevel",
		    XMLSEC_ERRORS_R_MAX_RETRIEVALS_LEVEL,
		    "%d", keyInfoCtx->encKeysLevel);
	return(-1);
    }
    
    ++keyInfoCtx->encKeysLevel;

    /**
     * Init Enc context
     */    
    encCtx = xmlSecEncCtxCreate(keyInfoCtx->keysMngr);
    if(encCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    "xmlSecEncCtxCreate",
	    	    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecEncCtxCreate");
	goto done;
    }
    encCtx->ignoreType = 1; /* do not substitute the node! */
    
    ret = xmlSecDecrypt(encCtx, keyInfoCtx->context, NULL, node, &encResult);
    if((ret < 0) || (encResult == NULL) || (encResult->buffer == NULL)){
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    "xmlSecDecrypt",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "%d", ret);
	goto done;
    } 

    ret = xmlSecKeyDataBinRead(keyInfoCtx->keyId, key,
			   xmlSecBufferGetData(encResult->buffer),
			   xmlSecBufferGetSize(encResult->buffer),
			   keyInfoCtx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    "xmlSecKeyDataBinRead",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }			   
    
    res = 0; /* success */

done:
    if(encResult != NULL) {
	xmlSecEncResultDestroy(encResult);
    }
    if(encCtx != NULL) {
	xmlSecEncCtxDestroy(encCtx);
    }    
    return(res);
}

static int 
xmlSecKeyDataEncryptedKeyXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key, xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecEncCtxPtr encCtx = NULL;
    xmlSecKeyDataType type;
    unsigned char *keyBuf = NULL;
    size_t keySize = 0;
    int ret;
    int res = -1;

    xmlSecAssert2(id == xmlSecKeyDataEncryptedKeyId, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    
    if(!xmlSecKeyIsValid(key)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    "xmlSecKeyIsValid",
		    XMLSEC_ERRORS_R_INVALID_KEY,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    /* dump key to a binary buffer */
    /* TODO: parameter for enc key type? */
    type = keyInfoCtx->keyType;
    keyInfoCtx->keyType = xmlSecKeyDataTypeAny;
    ret = xmlSecKeyDataBinWrite(key->value->id, key, &keyBuf, &keySize, keyInfoCtx);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    "xmlSecKeyDataBinWrite",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }
    keyInfoCtx->keyType = type;
    
    /**
     * Init Enc context
     */    
    encCtx = xmlSecEncCtxCreate(keyInfoCtx->keysMngr);
    if(encCtx == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    "xmlSecEncCtxCreate",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }
    encCtx->ignoreType = 1; /* do not substitute the node! */

    ret = xmlSecEncryptMemory(encCtx, keyInfoCtx->context, NULL, node, keyBuf, keySize, NULL);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecKeyDataKlassGetName(id),
		    "xmlSecEncryptMemory",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	goto done;
    }
    
    res = 0;

done:
    if(keyBuf != NULL) {
	memset(keyBuf, 0, keySize);
	xmlFree(keyBuf); keyBuf = NULL;
    }
    if(encCtx != NULL) {
	xmlSecEncCtxDestroy(encCtx);
    }    
    return(res);
}

#endif /* XMLSEC_NO_XMLENC */


