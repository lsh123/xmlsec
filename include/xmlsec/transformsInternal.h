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

typedef unsigned long 				xmlSecTransformUsage;

/**
 * Forward typedefs 
 */
typedef struct _xmlSecTransformState		xmlSecTransformState, 
						*xmlSecTransformStatePtr;

typedef struct _xmlSecBinTransform 		xmlSecBinTransform, 
						*xmlSecBinTransformPtr; 
typedef struct xmlSecBinTransformIdStruct	xmlSecBinTransformIdStruct;
typedef const struct _xmlSecBinTransformIdStruct *xmlSecBinTransformId;

typedef struct _xmlSecXmlTransform 		xmlSecXmlTransform, 
						*xmlSecXmlTransformPtr; 
typedef struct _xmlSecXmlTransformIdStruct 	xmlSecXmlTransformIdStruct;
typedef const struct _xmlSecXmlTransformIdStruct *xmlSecXmlTransformId;


typedef struct _xmlSecC14NTransform		xmlSecC14NTransform, 
						*xmlSecC14NTransformPtr; 
typedef struct _xmlSecC14NTransformIdStruct 	xmlSecC14NTransformIdStruct;
typedef const struct _xmlSecC14NTransformIdStruct *xmlSecC14NTransformId;


/**
 * enum xmlSecTransformType:
 *
 * The transform input/output.
 */
typedef enum  {
    xmlSecTransformTypeBinary,	/* input: binary; output: binary */
    xmlSecTransformTypeXml,	/* input: XML; output: XML */
    xmlSecTransformTypeC14N	/* input: XML; output: binary */
} xmlSecTransformType;

/**
 * enum xmlSecBinTransformSubType:
 *
 * Binary transform sub-types.
 */
typedef enum  {
    xmlSecBinTransformSubTypeNone = 0,	/* unknown */
    xmlSecBinTransformSubTypeDigest,	/* digest */
    xmlSecBinTransformSubTypeCipher, 	/* cipher */
    xmlSecBinTransformSubTypeBuffered	/* buffered transform */
} xmlSecBinTransformSubType;

/**
 * enum xmlSecTransformResult:
 *
 * The transform result types.
 */
typedef enum  {
    xmlSecTransformResultBinary,	/* binary data */
    xmlSecTransformResultXml		/* XML document plus nodes set */
} xmlSecTransformResult;


/***************************************************************************
 *
 * Transforms State
 *
 **************************************************************************/
/**
 * struct xmlSecTransformState: 
 * 
 * The current transforms state.
 */
struct _xmlSecTransformState {
    /* initial state */
    xmlDocPtr				initDoc;	/* the pointer to the original xml document */
    xmlSecNodeSetPtr			initNodeSet;	/* the original nodes set */
    char				*initUri;	/* the original uri */

    /* current state: xml */    
    xmlDocPtr				curDoc;		/* the pointer to the current doc */
    xmlSecNodeSetPtr			curNodeSet;	/* the pointer to the current nodes set */
    
    /* current state: binary */
    xmlBufferPtr			curBuf;		/* the pointer to the current binary data */
    xmlSecTransformPtr			curFirstBinTransform; /* the pointer to the first pending binary transform */
    xmlSecTransformPtr			curLastBinTransform;  /* the pointer to the last pending binary transform */

    /*  optimization: special case for c14n transforms */
    xmlSecTransformPtr			curC14NTransform; /* the current pending c14n transform */
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
 * struct xmlSecTransformIdStruct:
 * 
 * The transform id structure.
 */
struct _xmlSecTransformIdStruct {
    /* data */
    xmlSecTransformType			type;	/* the type */
    xmlSecTransformUsage		usage;	/* the usage */
    const xmlChar			*href;  /* the algorithm href */

    /* methods */
    xmlSecTransformCreateMethod		create;	/* creation method */
    xmlSecTransformDestroyMethod	destroy;/* destroy method */
    xmlSecTransformReadNodeMethod	read;	/* xml node read method */
};

/**
 * struct xmlSecTransform:
 *
 * The transform structure.
 */
struct _xmlSecTransform {
    xmlSecTransformId 			id;    	/* the transform id (#xmlSecTransformIdStruct) */
    xmlSecTransformStatus		status; /* the transform status (ok/fail/unknown) */
    int					dontDestroy; /* the don't automatically destroy flag */
    void				*data;	/* the pointer to transform specific data */
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

void 			xmlSecTransformsInit		(void);
int			xmlSecTransformsNodeRead	(xmlSecTransformStatePtr state, 
							 xmlNodePtr transformsNode);
xmlSecTransformId	xmlSecTransformFind		(const xmlChar *href);
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
							 xmlSecKeyPtr key);
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
 * struct xmlSecBinTransformIdStruct:
 * 
 * The binary transform id (%xmlSecTransformTypeBinary type).
 */ 
struct _xmlSecBinTransformIdStruct {
    /* same as xmlSecTransformId */    
    /* data */
    xmlSecTransformType			type;	/* the type */
    xmlSecTransformUsage		usage;	/* the usage */
    const xmlChar			*href;  /* the algorithm href */

    /* methods */
    xmlSecTransformCreateMethod		create;	/* creation method */
    xmlSecTransformDestroyMethod	destroy;/* destroy method */
    xmlSecTransformReadNodeMethod	read;	/* xml node read method */

    /* xmlSecBinTransform data/methods */
    /* data */
    xmlSecKeyId				keyId;	/* the transform's key id */
    xmlSecKeyType			encryption; /* the key type (public/private) for encryption */
    xmlSecKeyType			decryption; /* the key type (public/private) for encryption */
    xmlSecBinTransformSubType		binSubType; /* the transform's binary sub type */
    
    /* methods */        
    xmlSecBinTransformAddKeyMethod	addBinKey;  /* add key method */
    xmlSecBinTransformReadMethod	readBin;    /* read binary data method */ 
    xmlSecBinTransformWriteMethod	writeBin;   /* write binary data method */
    xmlSecBinTransformFlushMethod	flushBin;   /* flush binary data method */
};

/**
 * struct xmlSecBinTransform:
 *
 * Binary transforms are very similar to BIO from OpenSSL.
 * However,there is one big difference. In OpenSSL BIO writing 
 * operation *always* encrypts data and read operation *always*
 * decrypts data. We do not want to have this restriction.
 */ 
struct _xmlSecBinTransform {	
    /* same as for xmlSecTransform but id type changed */
    xmlSecBinTransformId 		id;    	/* the transform id (#xmlSecTransformIdStruct) */
    xmlSecTransformStatus		status; /* the transform status (ok/fail/unknown) */
    int					dontDestroy; /* the don't automatically destroy flag */
    void				*data;	/* the pointer to transform specific data */

    /* xmlSecBinTransform specific */
    int					encode;	/* encode/decode (encrypt/decrypt) flag */
    xmlSecBinTransformPtr		next;	/* next binary transform in the chain */
    xmlSecBinTransformPtr		prev;   /* previous binary transform in the chain */
    void				*binData;/* the pointer to binary transform speific data */
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
	  xmlSecKeyIdUnknown)
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
	  xmlSecKeyTypeAny)
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
	  xmlSecKeyTypeAny)

int  			xmlSecTransformAddKey		(xmlSecTransformPtr transform, 
							 xmlSecKeyPtr key);
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
 * struct _xmlSecXmlTransformIdStruct:
 * 
 * The xml transform id (%xmlSecTransformTypeXml type).
 */ 
struct _xmlSecXmlTransformIdStruct {
    /* same as xmlSecTransformId */    
    /* data */
    xmlSecTransformType			type;	/* the type */
    xmlSecTransformUsage		usage;	/* the usage */
    const xmlChar			*href;  /* the algorithm href */

    /* methods */
    xmlSecTransformCreateMethod		create;	/* creation method */
    xmlSecTransformDestroyMethod	destroy;/* destroy method */
    xmlSecTransformReadNodeMethod	read;	/* xml node read method */

    
    /* xmlTransform info */
    /* method */
    xmlSecXmlTransformExecuteMethod	executeXml; /* the execute method */
};

/**
 * struct xmlSecXmlTransform:
 *
 * The XML transform structure.
 */
struct _xmlSecXmlTransform {
    /* same as for xmlSecTransform but id type changed */
    xmlSecXmlTransformId 		id;    	/* the transform id */
    xmlSecTransformStatus		status; /* the transform status (ok/fail/unknown) */
    int					dontDestroy; /* the don't automatically destroy flag */
    void				*data;	/* the pointer to transform specific data */

    /* xmlSecXmlTransform specific */
    xmlNodePtr				here;	 /* the pointer to transform's 
						  <dsig:Transform> node */
    void				*xmlData;/* the pointer to xml transform 
						  specific data */
};

int 			xmlSecXmlTransformExecute	(xmlSecTransformPtr transform,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr *doc,
							 xmlSecNodeSetPtr *nodes);
void			xmlSecXmlTransformSetHere	(xmlSecTransformPtr transform,
							 xmlNodePtr here);

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
 * struct xmlSecC14NTransformIdStruct:
 *
 * The C14N transform id structure (%xmlSecTransformTypeC14N type).
 */
struct _xmlSecC14NTransformIdStruct {
    /* same as xmlSecTransformId */    
    /* data */
    xmlSecTransformType			type;	/* the type */
    xmlSecTransformUsage		usage;	/* the usage */
    const xmlChar			*href;  /* the algorithm href */

    /* methods */
    xmlSecTransformCreateMethod		create;	/* creation method */
    xmlSecTransformDestroyMethod	destroy;/* destroy method */
    xmlSecTransformReadNodeMethod	read;	/* xml node read method */

    /* xmlC14nTransform specific */
    xmlSecC14NTransformExecuteMethod	executeC14N; /* the execute method */
};

/**
 * struct xmlSecC14NTransform:
 *
 * The C14N transform structure.
 */ 
struct _xmlSecC14NTransform {
    /* same as for xmlSecTransform but id type changed */
    xmlSecC14NTransformId 		id;    	/* the transform id */
    xmlSecTransformStatus		status; /* the transform status (ok/fail/unknown) */
    int					dontDestroy; /* the don't automatically destroy flag */
    void				*data;	/* the pointer to transform specific data */
    
    /* xmlSecC14NTransform specific */ 
    void				*c14nData; /* the pointer to transform specific data */
};

int 			xmlSecC14NTransformExecute	(xmlSecTransformPtr transform,
							 xmlDocPtr doc,
							 xmlSecNodeSetPtr nodes,
							 xmlOutputBufferPtr buffer);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_TRANSFORMS_INTERNAL_H__ */

