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
#include <xmlsec/keys.h>
#include <xmlsec/nodeset.h>


#define XMLSEC_TRANSFORM_BINARY_CHUNK			64

typedef const struct _xmlSecTransformKlass		xmlSecTransformKlass, *xmlSecTransformId;
typedef struct _xmlSecTransform 			xmlSecTransform, *xmlSecTransformPtr; 
typedef struct _xmlSecTransformCtx 			xmlSecTransformCtx, *xmlSecTransformCtxPtr; 

#include <xmlsec/transforms-old.h>

/**********************************************************************
 *
 * Hi-level functions
 *
 *********************************************************************/
int 			xmlSecTransformsInit		(void);
XMLSEC_EXPORT int	xmlSecTransformsRegister	(xmlSecTransformId keyId);
xmlSecTransformId	xmlSecTransformsFind		(const xmlChar *href,
							 xmlSecTransformUsage usage);


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
 * xmlSecTransformCtx
 *
 *************************************************************************/
/**
 * xmlSecTransformCtx:
 *
 * The transform context.
 */
struct _xmlSecTransformCtx {
    xmlDocPtr		ctxDoc;
};

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
XMLSEC_EXPORT int 			xmlSecTransformRead	(xmlSecTransformPtr transform,
								 xmlNodePtr node);
XMLSEC_EXPORT int  			xmlSecTransformSetKey	(xmlSecTransformPtr transform, 
								 xmlSecKeyPtr key);
XMLSEC_EXPORT int  			xmlSecTransformSetKeyReq(xmlSecTransformPtr transform, 
								 xmlSecKeyReqPtr keyReq);
XMLSEC_EXPORT int  			xmlSecTransformVerify	(xmlSecTransformPtr transform, 
								 const unsigned char* data,
								 size_t dataSize,
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
								 size_t* dataSize,
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int			xmlSecTransformDefaultPushXml(xmlSecTransformPtr transform, 
								 xmlSecNodeSetPtr nodes,
								 xmlSecTransformCtxPtr transformCtx);
XMLSEC_EXPORT int			xmlSecTransformDefaultPopXml(xmlSecTransformPtr transform, 
								 xmlSecNodeSetPtr* nodes,
								 xmlSecTransformCtxPtr transformCtx);


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
 * the @transformNode.
 *
 * Returns 0 on success or a negative value otherwise.
 */
typedef int 		(*xmlSecTransformNodeReadMethod)	(xmlSecTransformPtr transform,
								 xmlNodePtr node);

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

    /* obsolete */    
    xmlSecTransformExecuteXmlMethod	executeXml;
    xmlSecTransformExecuteC14NMethod	executeC14N;
};

#define xmlSecTransformKlassGetName(klass) \
	(((klass)) ? ((klass)->name) : NULL)

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

