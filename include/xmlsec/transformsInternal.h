/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_TRANSFORMS_INTERNAL_H__
#define __XMLSEC_TRANSFORMS_INTERNAL_H__    



#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/nodeset.h>



XMLSEC_EXPORT int 	xmlSecTransformIdsRegister		(xmlSecTransformId id);
XMLSEC_EXPORT int 	xmlSecTransformIdsRegisterDefault	(void);
XMLSEC_EXPORT void 	xmlSecTransformIdsUnregisterAll		(void);
XMLSEC_EXPORT xmlSecTransformId	xmlSecTransformIdsFindByHref	(const xmlChar *href);

/* 
 * Transforms usage constants
 */
/**
 * xmlSecUsageAny:
 *
 * Transform could be used for operation.
 */
#define xmlSecUsageAny				0
/**
 * xmlSecUsageDSigC14N:
 *
 * Transform could be used for C14N.
 */
#define xmlSecUsageDSigC14N			1
/**
 * xmlSecUsageDSigTransform:
 *
 * Transform could be used as a transform in XML DSig.
 */
#define xmlSecUsageDSigTransform		2
/**
 * xmlSecUsageDSigDigest:
 *
 * Transform could be used for digests.
 */
#define xmlSecUsageDSigDigest			4
/**
 * xmlSecUsageDSigSignature:
 *
 * Transform could be used for generating signatures.
 */
#define xmlSecUsageDSigSignature		8
/**
 * xmlSecUsageEncryptionMethod:
 *
 * Transform could be used for encryption.
 */
#define xmlSecUsageEncryptionMethod		16

/** 
 * xmlSecTransformUsage:
 *
 * The transform usage bits mask.
 */
typedef unsigned long 				xmlSecTransformUsage;

/**
 * Forward typedefs 
 */
typedef struct _xmlSecTransformState		xmlSecTransformState, 
						*xmlSecTransformStatePtr;

typedef struct _xmlSecBinTransform 		xmlSecBinTransform, 
						*xmlSecBinTransformPtr; 
typedef const struct _xmlSecBinTransformIdStruct *xmlSecBinTransformId;

typedef struct _xmlSecXmlTransform 		xmlSecXmlTransform, 
						*xmlSecXmlTransformPtr; 
typedef const struct _xmlSecXmlTransformIdStruct *xmlSecXmlTransformId;


typedef struct _xmlSecC14NTransform		xmlSecC14NTransform, 
						*xmlSecC14NTransformPtr; 
typedef const struct _xmlSecC14NTransformIdStruct *xmlSecC14NTransformId;


/**
 * xmlSecTransformType:
 * @xmlSecTransformTypeBinary: input - binary; output - binary.
 * @xmlSecTransformTypeXml: input - XML; output - XML.
 * @xmlSecTransformTypeC14N: input - XML; output - binary.
 *
 * The transform input/output types.
 */
typedef enum  {
    xmlSecTransformTypeBinary,
    xmlSecTransformTypeXml,
    xmlSecTransformTypeC14N
} xmlSecTransformType;

/**
 * xmlSecBinTransformSubType:
 * @xmlSecBinTransformSubTypeNone: unknown.
 * @xmlSecBinTransformSubTypeDigest: digest.
 * @xmlSecBinTransformSubTypeCipher: cipher.
 * @xmlSecBinTransformSubTypeBuffered: buffered transform.
 *
 * Binary transform sub-types.
 */
typedef enum {
    xmlSecBinTransformSubTypeNone = 0,
    xmlSecBinTransformSubTypeDigest,
    xmlSecBinTransformSubTypeCipher,
    xmlSecBinTransformSubTypeBuffered
} xmlSecBinTransformSubType;

/**
 * xmlSecTransformResult:
 * @xmlSecTransformResultBinary: binary data.
 * @xmlSecTransformResultXml: XML document plus nodes set.
 *
 * The transform result types.
 */
typedef enum {
    xmlSecTransformResultBinary,
    xmlSecTransformResultXml
} xmlSecTransformResult;


/***************************************************************************
 *
 * Transforms State
 *
 **************************************************************************/
/**
 * xmlSecTransformState: 
 * @initDoc: the pointer to the original xml document.
 * @initNodeSet: the original nodes set.
 * @initUri: the original uri.
 * @curDoc: the pointer to the current doc.
 * @curNodeSet:	the pointer to the current nodes set.
 * @curBuf: the pointer to the current binary data.
 * @curFirstBinTransform: the pointer to the first pending binary transform.
 * @curLastBinTransform: the pointer to the last pending binary transform.
 * @curC14NTransform: the current pending c14n transform.
 * 
 * The current transforms state.
 */
struct _xmlSecTransformState {
    /* initial state */
    xmlDocPtr				initDoc;
    xmlSecNodeSetPtr			initNodeSet;
    char				*initUri;

    /* current state: xml */    
    xmlDocPtr				curDoc;	
    xmlSecNodeSetPtr			curNodeSet;
    
    /* current state: binary */
    xmlBufferPtr			curBuf;	
    xmlSecTransformPtr			curFirstBinTransform; 
    xmlSecTransformPtr			curLastBinTransform; 

    /*  optimization: special case for c14n transforms */
    xmlSecTransformPtr			curC14NTransform; 
};

xmlSecTransformStatePtr	xmlSecTransformStateCreate	(xmlDocPtr doc,
							 xmlSecNodeSetPtr nodeSet,
							 const char *uri);
void			xmlSecTransformStateDestroy	(xmlSecTransformStatePtr state);
int			xmlSecTransformStateUpdate	(xmlSecTransformStatePtr state,
							 xmlSecTransformPtr transform);
int			xmlSecTransformStateFinal	(xmlSecTransformStatePtr state,
							 xmlSecTransformResult type);


/************************************************************************
 *
 * Transform 
 *
 ************************************************************************/ 
/**
 * xmlSecTransformCreateMethod:
 * @id: the transform id to create.
 *
 * The transform specific creation method.
 *
 * Returns pointer to the newly created transform or NULL if an 
 * error occurs.
 */
typedef xmlSecTransformPtr (*xmlSecTransformCreateMethod) (xmlSecTransformId id);
/**
 * xmlSecTransformDestroyMethod:
 * @transform: the pointer to the #xmlSecTransform structure.
 *
 * The transform specific destroy method.
 */
typedef void 	(*xmlSecTransformDestroyMethod)		  (xmlSecTransformPtr transform);
/**
 * xmlSecTransformReadNodeMethod:
 * @transform: the pointer to the #xmlSecTransform structure.
 * @transformNode: the pointer to the <dsig:Transform> node.
 *
 * The transfomr specific method to read the transform data from 
 * the @transformNode.
 *
 * Returns 0 on success or a negative value otherwise.
 */
typedef int 	(*xmlSecTransformReadNodeMethod)	  (xmlSecTransformPtr transform,
							   xmlNodePtr transformNode);
/**
 * xmlSecTransformId:
 * @type: the type.
 * @usage: the usage.
 * @href: the algorithm href.
 * @create: creation method.
 * @destroy: destroy method.
 * @read: xml node read method.
 * 
 * The transform id structure.
 */
struct _xmlSecTransformIdStruct {
    /* data */
    xmlSecTransformType			type;
    xmlSecTransformUsage		usage;
    const xmlChar			*href;

    /* methods */
    xmlSecTransformCreateMethod		create;
    xmlSecTransformDestroyMethod	destroy;
    xmlSecTransformReadNodeMethod	read;
};

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
    xmlSecTransformId 			id; 
    xmlSecTransformStatus		status;
    int					dontDestroy;
    void				*data;
};

/**
 * xmlSecTransformIsValid:
 * @transform: the pointer to transform.
 *
 * Macro. Returns 1 if the @transform is valid or 0 otherwise.
 */
#define xmlSecTransformIsValid(transform) \
	((( transform ) != NULL) && ((( transform )->id) != NULL))
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

int			xmlSecTransformsNodeRead	(xmlSecTransformStatePtr state, 
							 xmlNodePtr transformsNode);
xmlSecTransformPtr	xmlSecTransformNodeRead		(xmlNodePtr transformNode, 
							 xmlSecTransformUsage usage,
							 int dontDestroy);
int			xmlSecTransformNodeWrite	(xmlNodePtr transformNode,
							 xmlSecTransformId id);

xmlSecTransformPtr	xmlSecTransformCreate		(xmlSecTransformId id,
							 xmlSecTransformUsage usage,
							 int dontDestroy);
void			xmlSecTransformDestroy		(xmlSecTransformPtr transform,
							 int forceDestroy);
int 			xmlSecTransformRead		(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);

/**************************************************************************
 *
 * Binary transform
 *
 *************************************************************************/
/**
 * xmlSecBinTransformAddKeyMethod:
 * @transform: the pointer to binary transform.
 * @key: the pointer to key.
 *
 * The transform specific method to set key for use.
 * 
 * Returns 0 on success or a negative value otherwise.
 */
typedef int  	(*xmlSecBinTransformAddKeyMethod)	(xmlSecBinTransformPtr transform, 
							 xmlSecKeyValuePtr key);
/**
 * xmlSecBinTransformReadMethod:
 * @transform: the pointer to #xmlSecTransform structure.
 * @buf: the output buffer.
 * @size: the output buffer size.
 * 
 * The transform specific method to read next chunk of binary data into @buf.
 *
 * Returns the number of bytes in the buffer or negative value
 * if an error occurs.
 */
typedef int  	(*xmlSecBinTransformReadMethod)		(xmlSecBinTransformPtr transform, 
							 unsigned char *buf, 
							 size_t size);
/**
 * xmlSecBinTransformWriteMethod:
 * @transform: the pointer to #xmlSecTransform structure.
 * @buf: the input data buffer.
 * @size: the input data size.
 *
 * The transform specific method to write next chunk of binary data from @buf.
 * 
 * Returns 0 if success or a negative value otherwise.
 */
typedef int  	(*xmlSecBinTransformWriteMethod)	(xmlSecBinTransformPtr transform, 
                                        		 const unsigned char *buf, 
							 size_t size);
/**
 * xmlSecBinTransformFlushMethod:
 * @transform: the pointer to #xmlSecTransform structure.
 *
 * The transform specific method to finalize writing. 
 *
 * Returns 0 if success or negative value otherwise.
 */
typedef int  	(*xmlSecBinTransformFlushMethod)	(xmlSecBinTransformPtr transform);

/**
 * xmlSecBinTransformId:
 * @type: the type.
 * @usage: the usage.
 * @href: the algorithm href.
 * @create: creation method.
 * @destroy: destroy method.
 * @read: xml node read method.
 * @keyId: the transform's key id.
 * @encryption: the key type (public/private) for encryption.
 * @decryption: the key type (public/private) for encryption.
 * @binSubType: the transform's binary sub type.
 * @addBinKey:  add key method.
 * @readBin: read binary data method.
 * @writeBin: write binary data method.
 * @flushBin: flush binary data method.
 * 
 * The binary transform id (%xmlSecTransformTypeBinary type).
 */ 
struct _xmlSecBinTransformIdStruct {
    /* same as xmlSecTransformId */    
    /* data */
    xmlSecTransformType			type;
    xmlSecTransformUsage		usage;
    const xmlChar			*href;

    /* methods */
    xmlSecTransformCreateMethod		create;
    xmlSecTransformDestroyMethod	destroy;
    xmlSecTransformReadNodeMethod	read;

    /* xmlSecBinTransform data/methods */
    /* data */
    xmlSecKeyValueId			keyId;
    xmlSecKeyValueType			encryption;
    xmlSecKeyValueType			decryption;
    xmlSecBinTransformSubType		binSubType;
    
    /* methods */        
    xmlSecBinTransformAddKeyMethod	addBinKey; 
    xmlSecBinTransformReadMethod	readBin; 
    xmlSecBinTransformWriteMethod	writeBin;
    xmlSecBinTransformFlushMethod	flushBin;
};

/**
 * xmlSecBinTransform:
 * @id: the transform id (pointer to #xmlSecBinTransformId).
 * @status: the transform status (ok/fail/unknown).
 * @dontDestroy: the don't automatically destroy flag.
 * @data: the pointer to transform specific data.
 * @encode: encode/decode (encrypt/decrypt) flag.
 * @next: next binary transform in the chain.
 * @prev: previous binary transform in the chain.
 * @binData: the pointer to binary transform speific data.
 *
 * Binary transforms are very similar to BIO from OpenSSL.
 * However,there is one big difference. In OpenSSL BIO writing 
 * operation *always* encrypts data and read operation *always*
 * decrypts data. We do not want to have this restriction.
 */ 
struct _xmlSecBinTransform {	
    /* same as for xmlSecTransform but id type changed */
    xmlSecBinTransformId 		id; 
    xmlSecTransformStatus		status;
    int					dontDestroy;
    void				*data;

    /* xmlSecBinTransform specific */
    int					encode;
    xmlSecBinTransformPtr		next;
    xmlSecBinTransformPtr		prev;
    void				*binData;
};

/**
 * xmlSecBinTransformIdCheckKeyId:
 * @id: the transform id.
 * @kId: the key id.
 *
 * Macro. Returns 1 if the transform @id has #xmlSecTransformTypeBinary type
 * and the transform's keyId matches specified @kId or 0 otherwise.
 */
#define xmlSecBinTransformIdCheckKeyId(id, kId) \
	(((id) != NULL) && \
	 ((id)->type == xmlSecTransformTypeBinary) && \
	 (((xmlSecBinTransformId)(id))->keyId == kId))
/**
 * xmlSecBinTransformIdGetKeyId:
 * @id: the transform id.
 *
 * Macro. Returns the key id required by the transform or NULL if an error 
 * occurs.
 */
#define xmlSecBinTransformIdGetKeyId(id) \
	((((id) != NULL) && \
	 ((id)->type == xmlSecTransformTypeBinary)) ? \
	  ((xmlSecBinTransformId)(id))->keyId : \
	  xmlSecKeyValueIdUnknown)
/**
 * xmlSecBinTransformCheckSubType:
 * @transform: the pointer to transform.
 * @t: the transform's subtype.
 *
 * Macro. Returns 1 if the @transform is valid, has 
 * #xmlSecTransformTypeBinary type and has specified subtype @t 
 * or 0 otherwise.
 */
#define xmlSecBinTransformCheckSubType(transform, t) \
	(xmlSecTransformCheckType(( transform ), xmlSecTransformTypeBinary) && \
	((((xmlSecBinTransformId)(( transform )->id))->binSubType) == ( t )))
/**
 * xmlSecBinTransformIdGetEncKeyType:
 * @id: the transform id.
 *
 * Macro. Returns the encryption key type by the transform or NULL if 
 * an error occurs.
 */
#define xmlSecBinTransformIdGetEncKeyType(id) \
	((((id) != NULL) && \
	 ((id)->type == xmlSecTransformTypeBinary)) ? \
	  ((xmlSecBinTransformId)(id))->encryption : \
	  xmlSecKeyValueTypeAny)
/**
 * xmlSecBinTransformIdGetDecKeyType:
 * @id: the transform id.
 *
 * Macro. Returns the decryption key type by the transform or NULL if 
 * an error occurs.
 */
#define xmlSecBinTransformIdGetDecKeyType(id) \
	((((id) != NULL) && \
	 ((id)->type == xmlSecTransformTypeBinary)) ? \
	  ((xmlSecBinTransformId)(id))->decryption : \
	  xmlSecKeyValueTypeAny)

int  			xmlSecBinTransformAddKey	(xmlSecTransformPtr transform, 
							 xmlSecKeyValuePtr key);
int			xmlSecBinTransformRead		(xmlSecTransformPtr transform,
							 unsigned char *buf,
							 size_t size);		
int			xmlSecBinTransformWrite		(xmlSecTransformPtr transform,
							 const unsigned char *buf,
							 size_t size);		
int			xmlSecBinTransformFlush		(xmlSecTransformPtr transform);
xmlSecTransformPtr	xmlSecBinTransformAddAfter	(xmlSecTransformPtr curTransform,
							 xmlSecTransformPtr newTransform);
xmlSecTransformPtr	xmlSecBinTransformAddBefore	(xmlSecTransformPtr curTransform,
							 xmlSecTransformPtr newTransform);
void			xmlSecBinTransformRemove	(xmlSecTransformPtr transform);
void			xmlSecBinTransformDestroyAll	(xmlSecTransformPtr transform);	
void			xmlSecBinTransformSetEncrypt	(xmlSecTransformPtr transform, 
							 int encrypt);

/**************************************************************************
 *
 * XML Transform
 *
 *************************************************************************/
/**
 * xmlSecXmlTransformExecuteMethod:
 * @transform: the pointer to XML transform.
 * @ctxDoc: the pointer to the document containing the transform's 
 *		<dsig:Transform> node.
 * @doc: the pointer to the pointer to current document.
 * @nodes: the pointer to the pointer to current and result nodes set.
 *
 * Transform specific execute method. Returns result nodes set in @nodes.
 *
 * Returns 0 on success or a negative value otherwise.
 */
typedef int 	(*xmlSecXmlTransformExecuteMethod)	(xmlSecXmlTransformPtr transform,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr *doc,
							 xmlSecNodeSetPtr *nodes);
/** 
 * xmlSecXmlTransformId:
 * @type: the type.
 * @usage: the usage.
 * @href: the algorithm href.
 * @create: creation method.
 * @destroy: destroy method.
 * @read: xml node read method.
 * @executeXml: the execute method.
 * 
 * The xml transform id (%xmlSecTransformTypeXml type).
 */ 
struct _xmlSecXmlTransformIdStruct {
    /* same as xmlSecTransformId */    
    /* data */
    xmlSecTransformType			type;
    xmlSecTransformUsage		usage;
    const xmlChar			*href;

    /* methods */
    xmlSecTransformCreateMethod		create;
    xmlSecTransformDestroyMethod	destroy;
    xmlSecTransformReadNodeMethod	read;

    
    /* xmlTransform info */
    /* method */
    xmlSecXmlTransformExecuteMethod	executeXml;
};

/**
 * xmlSecXmlTransform:
 * @id: the transform id (pointer to #xmlSecXmlTransformId).
 * @status: the transform status (ok/fail/unknown).
 * @dontDestroy: the don't automatically destroy flag.
 * @data: the pointer to transform specific data.
 * @here: the pointer to transform's <dsig:Transform> node.
 * @xmlData: the pointer to xml transform  specific data.
 *
 * The XML transform structure.
 */
struct _xmlSecXmlTransform {
    /* same as for xmlSecTransform but id type changed */
    xmlSecXmlTransformId 		id; 
    xmlSecTransformStatus		status;
    int					dontDestroy;
    void				*data;

    /* xmlSecXmlTransform specific */
    xmlNodePtr				here;
    void				*xmlData;
};

int 			xmlSecXmlTransformExecute	(xmlSecTransformPtr transform,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr *doc,
							 xmlSecNodeSetPtr *nodes);

/*************************************************************************
 *
 * C14N Transform
 *
 ************************************************************************/
/**
 * xmlSecC14NTransformExecuteMethod:
 * @transform: the pointer to C14N transform.
 * @doc: the pointer to current document.
 * @nodes: the pointer to current nodes set.
 * @buffer: the result buffer.
 *
 * Transform specific execute method. returns result in the @buffer.
 *
 * Returns 0 on success or a negative value otherwise.
 */
typedef int 	(*xmlSecC14NTransformExecuteMethod)	(xmlSecC14NTransformPtr transform,
							 xmlDocPtr doc,
							 xmlSecNodeSetPtr nodes,
							 xmlOutputBufferPtr buffer);
/**
 * xmlSecC14NTransformId:
 * @type: the type.
 * @usage: the usage.
 * @href: the algorithm href.
 * @create: creation method.
 * @destroy: destroy method.
 * @read: xml node read method.
 * @executeC14N: the execute method.
 *
 * The C14N transform id structure (%xmlSecTransformTypeC14N type).
 */
struct _xmlSecC14NTransformIdStruct {
    /* same as xmlSecTransformId */    
    /* data */
    xmlSecTransformType			type;
    xmlSecTransformUsage		usage;
    const xmlChar			*href;

    /* methods */
    xmlSecTransformCreateMethod		create;
    xmlSecTransformDestroyMethod	destroy;
    xmlSecTransformReadNodeMethod	read;

    /* xmlC14nTransform specific */
    xmlSecC14NTransformExecuteMethod	executeC14N;
};

/**
 * xmlSecC14NTransform:
 * @id: the transform id (pointer to #xmlSecC14NTransformId).
 * @status: the transform status (ok/fail/unknown).
 * @dontDestroy: the don't automatically destroy flag.
 * @data: the pointer to transform specific data.
 * @c14nData: the pointer to transform specific data.
 *
 * The C14N transform structure.
 */ 
struct _xmlSecC14NTransform {
    /* same as for xmlSecTransform but id type changed */
    xmlSecC14NTransformId 		id; 
    xmlSecTransformStatus		status;
    int					dontDestroy;
    void				*data;
    
    /* xmlSecC14NTransform specific */ 
    void				*c14nData;
};

int 			xmlSecC14NTransformExecute	(xmlSecTransformPtr transform,
							 xmlDocPtr doc,
							 xmlSecNodeSetPtr nodes,
							 xmlOutputBufferPtr buffer);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_TRANSFORMS_INTERNAL_H__ */

