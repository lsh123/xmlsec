/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_TRANSFORMS_H__
#define __XMLSEC_TRANSFORMS_H__    



#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/list.h>
#include <xmlsec/nodeset.h>
#include <xmlsec/keys.h>

#define XMLSEC_TRANSFORM_BINARY_CHUNK			64

typedef const struct _xmlSecTransformKlass		xmlSecTransformKlass, *xmlSecTransformId;
typedef unsigned int					xmlSecTransformUsage;

#include <xmlsec/transforms-old.h>

/**********************************************************************
 *
 * Hi-level functions
 *
 *********************************************************************/
XMLSEC_EXPORT xmlSecPtrListPtr	xmlSecTransformIdsGet		(void);
XMLSEC_EXPORT int 		xmlSecTransformIdsInit		(void);
XMLSEC_EXPORT void 		xmlSecTransformIdsShutdown	(void);
XMLSEC_EXPORT int 		xmlSecTransformIdsRegisterDefault(void);
XMLSEC_EXPORT int		xmlSecTransformIdsRegister	(xmlSecTransformId keyId);

/************************************************************************** 
 *
 * xmlSecTransformStatus
 *
 *************************************************************************/
/**
 * xmlSecTransformStatus:
 * @xmlSecTransformStatusNone: the status unknown.
 * @xmlSecTransformStatusOk: success.
 * @xmlSecTransformStatusFail: an error occur.
 *
 * The transform execution result.
 */
typedef enum  {
    xmlSecTransformStatusNone = 0,
    xmlSecTransformStatusWorking,
    xmlSecTransformStatusFinished,
    xmlSecTransformStatusOk,
    xmlSecTransformStatusFail
} xmlSecTransformStatus;
		    
/**************************************************************************
 *
 * xmlSecTransformMode
 *
 *************************************************************************/
typedef enum  {
    xmlSecTransformModeNone = 0,
    xmlSecTransformModePush,
    xmlSecTransformModePop
} xmlSecTransformMode;

typedef unsigned int		xmlSecUriType;
#define xmlSecUriTypeNone		0x0000
#define xmlSecUriTypeLocalEmpty		0x0001
#define xmlSecUriTypeLocalXPointer	0x0002		
#define xmlSecUriTypeRemote		0x0004
#define xmlSecUriTypeAny		0xFFFF
XMLSEC_EXPORT int 			xmlSecUriTypeCheck		(xmlSecUriType type,
									 const xmlChar* uri);
/**************************************************************************
 *
 * xmlSecTransformDataType
 *
 *************************************************************************/
typedef unsigned char			xmlSecTransformDataType;
#define xmlSecTransformDataTypeUnknown	0x00
#define xmlSecTransformDataTypeBin	0x01
#define xmlSecTransformDataTypeXml	0x02

/**************************************************************************
 *
 * xmlSecTransformUsage
 *
 *************************************************************************/
#define xmlSecTransformUsageUnknown			0x0000
/**
 * xmlSecTransformUsageDSigTransform:
 *
 * Transform could be used in <dsig:Transform>.
 */
#define xmlSecTransformUsageDSigTransform		0x0001
/**
 * xmlSecTransformUsageC14NMethod:
 *
 * Transform could be used in <dsig:CanonicalizationMethod>.
 */
#define xmlSecTransformUsageC14NMethod			0x0002
/**
 * xmlSecTransformUsageDigestMethod:
 *
 * Transform could be used in <dsig:DigestMethod>.
 */
#define xmlSecTransformUsageDigestMethod		0x0004
/**
 * xmlSecTransformUsageSignatureMethod:
 *
 * Transform could be used in <dsig:SignatureMethod>.
 */
#define xmlSecTransformUsageSignatureMethod		0x0008
/**
 * xmlSecTransformUsageEncryptionMethod:
 *
 * Transform could be used in <enc:EncryptionMethod>.
 */
#define xmlSecTransformUsageEncryptionMethod		0x0010
/**
 * xmlSecTransformUsageAny:
 *
 * Transform could be used for operation.
 */
#define xmlSecTransformUsageAny				0xFFFF

/**************************************************************************
 *
 * xmlSecTransformCtx
 *
 *************************************************************************/
/**
 * xmlSecTransformCtx:
 *
 * The transform context.
 */
struct _xmlSecTransformCtx {
    xmlSecUriType		allowedUris;
    xmlSecTransformStatus	status;
    xmlChar*			uri;
    xmlChar*			xptrExpr;
                
    xmlSecTransformPtr		first;
    xmlSecTransformPtr		last;
    xmlSecBufferPtr		result;
};

XMLSEC_EXPORT int 			xmlSecTransformCtxInitialize	(xmlSecTransformCtxPtr ctx);
XMLSEC_EXPORT void			xmlSecTransformCtxFinalize  	(xmlSecTransformCtxPtr ctx);
XMLSEC_EXPORT xmlSecTransformCtxPtr	xmlSecTransformCtxCreate    	(void);
XMLSEC_EXPORT void			xmlSecTransformCtxDestroy   	(xmlSecTransformCtxPtr ctx);
XMLSEC_EXPORT int			xmlSecTransformCtxSetUri	(xmlSecTransformCtxPtr ctx,
									 const xmlChar* uri,
									 xmlNodePtr hereNode);
XMLSEC_EXPORT int 			xmlSecTransformCtxAppend    	(xmlSecTransformCtxPtr ctx,
									 xmlSecTransformPtr transform);
XMLSEC_EXPORT int 			xmlSecTransformCtxPrepend	(xmlSecTransformCtxPtr ctx,
									 xmlSecTransformPtr transform);
XMLSEC_EXPORT xmlSecTransformPtr	xmlSecTransformCtxCreateAndAppend(xmlSecTransformCtxPtr ctx,
									 xmlSecTransformId id);
XMLSEC_EXPORT xmlSecTransformPtr	xmlSecTransformCtxCreateAndPrepend(xmlSecTransformCtxPtr ctx,
									 xmlSecTransformId id);
XMLSEC_EXPORT xmlSecTransformPtr 	xmlSecTransformCtxNodeRead	(xmlSecTransformCtxPtr ctx,
									 xmlNodePtr node,
									 xmlSecTransformUsage usage);
XMLSEC_EXPORT int			xmlSecTransformCtxNodesListRead	(xmlSecTransformCtxPtr ctx,
									 xmlNodePtr node,
									 xmlSecTransformUsage usage);
XMLSEC_EXPORT int			xmlSecTransformCtxPrepare	(xmlSecTransformCtxPtr ctx,
									 xmlSecTransformDataType inputDataType);
XMLSEC_EXPORT int			xmlSecTransformCtxBinaryExecute	(xmlSecTransformCtxPtr ctx, 
									 const unsigned char* data, 
									 size_t dataSize);
XMLSEC_EXPORT int 			xmlSecTransformCtxUriExecute	(xmlSecTransformCtxPtr ctx, 
									 const xmlChar* uri);
XMLSEC_EXPORT int			xmlSecTransformCtxXmlExecute	(xmlSecTransformCtxPtr ctx, 
									 xmlSecNodeSetPtr nodes);
XMLSEC_EXPORT int			xmlSecTransformCtxExecute	(xmlSecTransformCtxPtr ctx,
									 xmlDocPtr doc);
XMLSEC_EXPORT void			xmlSecTransformCtxDebugDump 	(xmlSecTransformCtxPtr ctx,
								        FILE* output);
XMLSEC_EXPORT void			xmlSecTransformCtxDebugXmlDump	(xmlSecTransformCtxPtr ctx,
									 FILE* output);
	
/**************************************************************************
 *
 * xmlSecTransform
 *
 *************************************************************************/
/**
 * xmlSecTransform:
 * @id: the transform id (pointer to #xmlSecTransformId).
 * @status: the transform status (ok/fail/unknown).
 * @dontDestroy: the don't automatically destroy flag.
 * @data: the pointer to transform specific data.
 *
 * The transform structure.
 */
struct _xmlSecTransform {
    /* general data */
    xmlSecTransformId 			id; 
    xmlSecTransformStatus		status;
    int					dontDestroy;
    xmlSecTransformPtr			next;
    xmlSecTransformPtr			prev;

    /* binary specific */
    int					encode;
    
    /* xml specific */
    xmlNodePtr				hereNode;

    /* binary data */
    xmlSecBuffer			inBuf;
    xmlSecBuffer			outBuf;
        
    /* xml data */
    xmlSecNodeSetPtr			inNodes;
    xmlSecNodeSetPtr			outNodes;

    /* reserved for the future */    
    void*				reserved0;
    void*				reserved1;
};

XMLSEC_EXPORT xmlSecTransformPtr	xmlSecTransformCreate	(xmlSecTransformId id,
								 int dontDestroy);
XMLSEC_EXPORT void			xmlSecTransformDestroy	(xmlSecTransformPtr transform,
								 int forceDestroy);
xmlSecTransformPtr			xmlSecTransformNodeRead	(xmlNodePtr node, 
								 xmlSecTransformUsage usage,
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int			xmlSecTransformPump	(xmlSecTransformPtr left,
								 xmlSecTransformPtr right,
    								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int  			xmlSecTransformSetKey	(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
XMLSEC_EXPORT int  			xmlSecTransformSetKeyReq(xmlSecTransformPtr transform, 
								 xmlSecKeyReqPtr keyReq);
XMLSEC_EXPORT int  			xmlSecTransformVerify	(xmlSecTransformPtr transform, 
								 const unsigned char* data,
								 size_t dataSize,
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int  			xmlSecTransformVerifyNodeContent(xmlSecTransformPtr transform, 
								 xmlNodePtr node,
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT xmlSecTransformDataType	xmlSecTransformGetDataType(xmlSecTransformPtr transform,
								 xmlSecTransformMode mode,
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int			xmlSecTransformPushBin	(xmlSecTransformPtr transform, 
								 const unsigned char* data,
								 size_t dataSize,
								 int final,
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int			xmlSecTransformPopBin	(xmlSecTransformPtr transform, 
								 unsigned char* data,
								 size_t maxDataSize,
								 size_t* dataSize,
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int			xmlSecTransformPushXml	(xmlSecTransformPtr transform, 
								 xmlSecNodeSetPtr nodes,
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int			xmlSecTransformPopXml	(xmlSecTransformPtr transform, 
								 xmlSecNodeSetPtr* nodes,
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int 			xmlSecTransformExecute	(xmlSecTransformPtr transform, 
								 int last, 
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT void			xmlSecTransformDebugDump(xmlSecTransformPtr transform,
								 FILE* output);
XMLSEC_EXPORT void			xmlSecTransformDebugXmlDump(xmlSecTransformPtr transform,
								 FILE* output);

#define xmlSecTransformGetName(transform) \
	((xmlSecTransformIsValid((transform))) ? \
	  xmlSecTransformKlassGetName((transform)->id) : NULL)

/**
 * xmlSecTransformIsValid:
 * @transform: the pointer to transform.
 *
 * Macro. Returns 1 if the @transform is valid or 0 otherwise.
 */
#define xmlSecTransformIsValid(transform) \
	((( transform ) != NULL) && \
	 (( transform )->id != NULL) && \
	 (( transform )->id->klassSize >= sizeof(xmlSecTransformKlass)) && \
	 (( transform )->id->objSize >= sizeof(xmlSecTransform)) && \
	 (( transform )->id->name != NULL))
 
/**
 * xmlSecTransformCheckType:
 * @transform: the pointer to transform.
 * @t: the transform type.
 *
 * Macro. Returns 1 if the @transform is valid and has specified type @t 
 * or 0 otherwise.
 */
#define xmlSecTransformCheckType(transform, t) \
 	(xmlSecTransformIsValid(( transform )) && \
	((( transform )->id->type) == ( t )))

/**
 * xmlSecTransformCheckId:
 * @transform: the pointer to transform.
 * @i: the transform id.
 *
 * Macro. Returns 1 if the @transform is valid and has specified id @i 
 * or 0 otherwise.
 */
#define xmlSecTransformCheckId(transform, i) \
 	(xmlSecTransformIsValid(( transform )) && \
	((((const xmlSecTransformId) (( transform )->id))) == ( i )))

/**
 * xmlSecTransformCheckSize:
 * @transform: the pointer to transform.
 * @size: the transform object size.
 *
 * Macro. Returns 1 if the @transform is valid and has at least @size
 * bytes or 0 otherwise.
 */
#define xmlSecTransformCheckSize(transform, size) \
 	(xmlSecTransformIsValid(( transform )) && \
	((( transform )->id->objSize) >= ( size )))


/************************************************************************
 *
 * Operations on transforms chain
 *
 ************************************************************************/ 
XMLSEC_EXPORT int			xmlSecTransformConnect	(xmlSecTransformPtr left,
								 xmlSecTransformPtr right,
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT xmlSecTransformPtr	xmlSecTransformAddAfter	(xmlSecTransformPtr curTransform,
								 xmlSecTransformPtr newTransform);
XMLSEC_EXPORT xmlSecTransformPtr	xmlSecTransformAddBefore(xmlSecTransformPtr curTransform,
								 xmlSecTransformPtr newTransform);
XMLSEC_EXPORT void			xmlSecTransformRemove	(xmlSecTransformPtr transform);

/************************************************************************
 *
 * Default callbacks, most of the transforms can use them
 *
 ************************************************************************/ 
XMLSEC_EXPORT xmlSecTransformDataType	xmlSecTransformDefaultGetDataType(xmlSecTransformPtr transform,
								 xmlSecTransformMode mode,
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int			xmlSecTransformDefaultPushBin(xmlSecTransformPtr transform, 
								 const unsigned char* data,
								 size_t dataSize,
								 int final,
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int			xmlSecTransformDefaultPopBin(xmlSecTransformPtr transform, 
								 unsigned char* data,
								 size_t maxDataSize,
								 size_t* dataSize,
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int			xmlSecTransformDefaultPushXml(xmlSecTransformPtr transform, 
								 xmlSecNodeSetPtr nodes,
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int			xmlSecTransformDefaultPopXml(xmlSecTransformPtr transform, 
								 xmlSecNodeSetPtr* nodes,
								 xmlSecTransformCtxPtr transformCtx);

/************************************************************************
 *
 * IO buffers for transforms
 *
 ************************************************************************/ 
XMLSEC_EXPORT xmlOutputBufferPtr 	xmlSecTransformCreateOutputBuffer(xmlSecTransformPtr transform, 
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT xmlParserInputBufferPtr 	xmlSecTransformCreateInputBuffer(xmlSecTransformPtr transform, 
								 xmlSecTransformCtxPtr transformCtx);

/************************************************************************
 *
 * Transform Klass
 *
 ************************************************************************/ 
/**
 * xmlSecTransformIdUnknown:
 *
 * The "unknown" transform id (NULL).
 */
#define xmlSecTransformIdUnknown			NULL

/**
 * xmlSecTransformInitializeMethod:
 * @transform: the transform.
 *
 * The transform specific creation method.
 *
 */
typedef int		(*xmlSecTransformInitializeMethod) 	(xmlSecTransformPtr transform);

/**
 * xmlSecTransformFinalizeMethod:
 * @transform: the pointer to the #xmlSecTransform structure.
 *
 * The transform specific destroy method.
 */
typedef void 		(*xmlSecTransformFinalizeMethod)	(xmlSecTransformPtr transform);

typedef xmlSecTransformDataType	(*xmlSecTransformGetDataTypeMethod)(xmlSecTransformPtr transform,
								 xmlSecTransformMode mode,
								 xmlSecTransformCtxPtr transformCtx);

/**
 * xmlSecTransformNodeReadMethod:
 * @transform: the pointer to the #xmlSecTransform structure.
 * @node: the pointer to the <dsig:Transform> node.
 *
 * The transfomr specific method to read the transform data from 
 * the @node.
 *
 * Returns 0 on success or a negative value otherwise.
 */
typedef int 		(*xmlSecTransformNodeReadMethod)	(xmlSecTransformPtr transform,
								 xmlNodePtr node,
								 xmlSecTransformCtxPtr transformCtx);

/**
 * xmlSecTransformSetKeyRequirements:
 * @transform: the pointer to #xmlSecTransform structure.
 * @keyInfoCtx: the pointer to key info context.
 * 
 */
typedef int  		(*xmlSecTransformSetKeyRequirements)	(xmlSecTransformPtr transform, 
								 xmlSecKeyReqPtr keyReq);

/**
 * xmlSecTransformSetKeyMethod:
 * @transform: the pointer to binary transform.
 * @key: the pointer to key.
 *
 * The transform specific method to set key for use.
 * 
 * Returns 0 on success or a negative value otherwise.
 */
typedef int  		(*xmlSecTransformSetKeyMethod)		(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);


typedef int  		(*xmlSecTransformVerifyMethod)		(xmlSecTransformPtr transform, 
								 const unsigned char* data,
								 size_t dataSize,
								 xmlSecTransformCtxPtr transformCtx);
typedef int		(*xmlSecTransformPushBinMethod)		(xmlSecTransformPtr transform, 
								 const unsigned char* data,
								 size_t dataSize,
								 int final,
								 xmlSecTransformCtxPtr transformCtx);
typedef int		(*xmlSecTransformPopBinMethod)		(xmlSecTransformPtr transform, 
								 unsigned char* data,
								 size_t maxDataSize,
								 size_t* dataSize,
								 xmlSecTransformCtxPtr transformCtx);
typedef int		(*xmlSecTransformPushXmlMethod)		(xmlSecTransformPtr transform, 
								 xmlSecNodeSetPtr nodes,
								 xmlSecTransformCtxPtr transformCtx);
typedef int		(*xmlSecTransformPopXmlMethod)		(xmlSecTransformPtr transform, 
								 xmlSecNodeSetPtr* nodes,
								 xmlSecTransformCtxPtr transformCtx);
typedef int  		(*xmlSecTransformExecuteMethod)		(xmlSecTransformPtr transform, 
								 int last,
								 xmlSecTransformCtxPtr transformCtx);

/**
 * xmlSecTransformKlass:
 * @type: the type.
 * @usage: the usage.
 * @href: the algorithm href.
 * @create: creation method.
 * @destroy: destroy method.
 * @read: xml node read method.
 * 
 * The transform id structure.
 */
struct _xmlSecTransformKlass {
    size_t				klassSize;
    size_t				objSize;

    /* general data */
    const xmlChar*			name;
    xmlSecTransformType			type;
    xmlSecTransformUsage		usage;
    const xmlChar			*href;

    /* general methods */
    xmlSecTransformInitializeMethod	initialize;
    xmlSecTransformFinalizeMethod	finalize;
    xmlSecTransformNodeReadMethod	readNode;    
    xmlSecTransformSetKeyRequirements	setKeyReq;
    xmlSecTransformSetKeyMethod		setKey;
    xmlSecTransformVerifyMethod		verify;
    xmlSecTransformGetDataTypeMethod	getDataType;
    xmlSecTransformPushBinMethod	pushBin;
    xmlSecTransformPopBinMethod		popBin;
    xmlSecTransformPushXmlMethod	pushXml;
    xmlSecTransformPopXmlMethod		popXml;
    
    /* low level method */
    xmlSecTransformExecuteMethod	execute;

    /* reserved for future */ 
    void* 				reserved0;
    void* 				reserved1;
};

#define xmlSecTransformKlassGetName(klass) \
	(((klass)) ? ((klass)->name) : NULL)

/***********************************************************************
 *
 * Transform Ids list
 *
 **********************************************************************/
#define xmlSecTransformIdListId	xmlSecTransformIdListGetKlass()
XMLSEC_EXPORT xmlSecPtrListId	xmlSecTransformIdListGetKlass	(void);
XMLSEC_EXPORT int		xmlSecTransformIdListFind	(xmlSecPtrListPtr list,
								 xmlSecTransformId transformId);
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformIdListFindByHref	(xmlSecPtrListPtr list,
								 const xmlChar* href,
								 xmlSecTransformUsage usage);
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformIdListFindByName	(xmlSecPtrListPtr list,
								 const xmlChar* name,
								 xmlSecTransformUsage usage);
/******************************************************************** 
 *
 * Base64 Transform
 *
 *******************************************************************/
#define XMLSEC_BASE64_LINESIZE			64
/**
 * XMLSEC_BASE64_LINESIZE:
 *
 * The default max line size for base64 encoding
 */ 
#define xmlSecTransformBase64Id \
	xmlSecTransformBase64GetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformBase64GetKlass		(void);
XMLSEC_EXPORT void 		xmlSecTransformBase64SetLineSize	(xmlSecTransformPtr transform,
									 size_t lineSize);

/********************************************************************
 *
 * C14N transforms 
 *
 *******************************************************************/
/**
 * xmlSecTransformInclC14NId:
 * 
 * The regular (inclusive) C14N without comments transform id.
 */
#define xmlSecTransformInclC14NId \
	xmlSecTransformInclC14NGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformInclC14NGetKlass		(void);

/**
 * xmlSecTransformInclC14NWithCommentsId:
 * 
 * The regular (inclusive) C14N with comments transform id.
 */
#define xmlSecTransformInclC14NWithCommentsId \
	xmlSecTransformInclC14NWithCommentsGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformInclC14NWithCommentsGetKlass(void);

/**
 * xmlSecTransformExclC14NId
 * 
 * The exclusive C14N without comments transform id.
 */
#define xmlSecTransformExclC14NId \
	xmlSecTransformExclC14NGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformExclC14NGetKlass		(void);

/**
 * xmlSecTransformExclC14NWithCommentsId:
 * 
 * The exclusive C14N with comments transform id.
 */
#define xmlSecTransformExclC14NWithCommentsId \
	xmlSecTransformExclC14NWithCommentsGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformExclC14NWithCommentsGetKlass(void);

/**
 * xmlSecTransformRemoveXmlTagsC14NId:
 * 
 * The "remove all xml tags" transform id (used before base64 transforms).
 */
#define xmlSecTransformRemoveXmlTagsC14NId \
	xmlSecTransformRemoveXmlTagsC14NGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformRemoveXmlTagsC14NGetKlass(void);

/********************************************************************
 *
 * Enveloped transform 
 *
 *******************************************************************/
/**
 * xmlSecTransformEnveloped:
 * 
 * The "enveloped" transform id.
 */
#define xmlSecTransformEnvelopedId \
	xmlSecTransformEnvelopedGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformEnvelopedGetKlass	(void);

/**
 * xmlSecTransformXPath:
 * 
 * The XPath transform id.
 */
#define xmlSecTransformXPathId \
	xmlSecTransformXPathGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformXPathGetKlass		(void);

/**
 * xmlSecTransformXPath2:
 * 
 * The XPath2 transform id.
 */
#define xmlSecTransformXPath2Id \
	xmlSecTransformXPath2GetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformXPath2GetKlass		(void);

/**
 * xmlSecTransformXPointer:
 * 
 * The XPointer transform id.
 */
#define xmlSecTransformXPointerId \
	xmlSecTransformXPointerGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformXPointerGetKlass		(void);
XMLSEC_EXPORT int		xmlSecTransformXPointerSetExpr		(xmlSecTransformPtr transform,
									 const xmlChar* expr,
									 xmlSecNodeSetType nodeSetType,
									 xmlNodePtr hereNode);

/********************************************************************
 *
 * XSLT transform 
 *
 *******************************************************************/
#ifndef XMLSEC_NO_XSLT
/**
 * xmlSecTransformXsltId:
 * 
 * The XSLT transform id.
 */
#define xmlSecTransformXsltId \
	xmlSecTransformXsltGetKlass()
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformXsltGetKlass		(void);
#endif /* XMLSEC_NO_XSLT */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_TRANSFORMS_H__ */

