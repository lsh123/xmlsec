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

/* 
 * Transforms usage constants
 */
#define xmlSecUsageAny				0
#define xmlSecUsageDSigC14N			1
#define xmlSecUsageDSigTransform		2
#define xmlSecUsageDSigDigest			4
#define xmlSecUsageDSigSignature		8
#define xmlSecUsageEncryptionMethod		16

typedef unsigned long 			xmlSecTransformUsage;
typedef struct _xmlSecBinTransform 	*xmlSecBinTransformPtr; 
typedef struct _xmlSecXmlTransform 	*xmlSecXmlTransformPtr; 
typedef struct _xmlSecC14NTransform	*xmlSecC14NTransformPtr; 
typedef struct _xmlSecTransformState	*xmlSecTransformStatePtr;


typedef enum _xmlSecTransformType {
    xmlSecTransformTypeBinary,
    xmlSecTransformTypeXml,
    xmlSecTransformTypeC14N
} xmlSecTransformType;

typedef enum _xmlSecBinTransformSubType {
    xmlSecBinTransformSubTypeNone = 0,
    xmlSecBinTransformSubTypeDigest,
    xmlSecBinTransformSubTypeCipher,
    xmlSecBinTransformSubTypeBuffered
} xmlSecBinTransformSubType;


typedef enum _xmlSecTransformResult {
    xmlSecTransformResultBinary,
    xmlSecTransformResultXml
} xmlSecTransformResult;

/**
 * Transform 
 */ 
typedef xmlSecTransformPtr (*xmlSecTransformCreateMethod) (xmlSecTransformId id);
typedef void 	(*xmlSecTransformDestroyMethod)		  (xmlSecTransformPtr transform);
typedef int 	(*xmlSecTransformReadNodeMethod)	  (xmlSecTransformPtr transform,
							   xmlNodePtr transformNode);

struct _xmlSecTransformId {
    /* data */
    xmlSecTransformType			type;
    xmlSecTransformUsage		usage;
    const xmlChar			*href;

    /* methods */
    xmlSecTransformCreateMethod		create;
    xmlSecTransformDestroyMethod	destroy;
    xmlSecTransformReadNodeMethod	read;
};

typedef struct _xmlSecTransform {
    xmlSecTransformId 			id;    
    xmlSecTransformStatus		status;
    int					dontDestroy;
    void				*data;
} xmlSecTransform;

/**
 * Binary transform
 *
 * Binary transforms are very similar to BIO from OpenSSL.
 * However,there is one big difference. In OpenSSL BIO writing 
 * operation *always* encrypts data and read operation *always*
 * decrypts data. We do not want to have this restriction.
 *
 */ 
typedef int  	(*xmlSecBinTransformAddKeyMethod)	(xmlSecBinTransformPtr transform, 
							 xmlSecKeyPtr key);
typedef int  	(*xmlSecBinTransformReadMethod)		(xmlSecBinTransformPtr transform, 
							 unsigned char *buf, 
							 size_t size);
typedef int  	(*xmlSecBinTransformWriteMethod)	(xmlSecBinTransformPtr transform, 
                                        		 const unsigned char *buf, 
							 size_t size);
typedef int  	(*xmlSecBinTransformFlushMethod)	(xmlSecBinTransformPtr transform);

typedef const struct _xmlSecBinTransformId	*xmlSecBinTransformId;
struct _xmlSecBinTransformId {
    /* same as xmlSecTransformId */    
    xmlSecTransformType			type;
    xmlSecTransformUsage		usage;
    const xmlChar			*href;
    
    xmlSecTransformCreateMethod		create;
    xmlSecTransformDestroyMethod	destroy;
    xmlSecTransformReadNodeMethod	read;
    
    /* xmlSecBinTransform data/methods */
    xmlSecKeyId				keyId;
    xmlSecKeyType			encryption;
    xmlSecKeyType			decryption;
    xmlSecBinTransformSubType		binSubType;
            
    xmlSecBinTransformAddKeyMethod	addBinKey;
    xmlSecBinTransformReadMethod	readBin;
    xmlSecBinTransformWriteMethod	writeBin;
    xmlSecBinTransformFlushMethod	flushBin;    
};

typedef struct _xmlSecBinTransform {	
    /* same as for xmlSecTransform but id type changed */
    xmlSecBinTransformId		id;    
    xmlSecTransformStatus		status;
    int					dontDestroy;
    void				*data;
    
    /* xmlSecBinTransform specific */
    int					encode;
    xmlSecBinTransformPtr		next;
    xmlSecBinTransformPtr		prev;   
    void				*binData;
} xmlSecBinTransform;

/**
 * XML Transform
 */
typedef int 	(*xmlSecXmlTransformExecuteMethod)	(xmlSecXmlTransformPtr transform,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr *doc,
							 xmlNodeSetPtr *nodes);
typedef const struct _xmlSecXmlTransformId *xmlSecXmlTransformId;
struct _xmlSecXmlTransformId {
    /* same as xmlSecTransformId */ 
    xmlSecTransformType			type;
    xmlSecTransformUsage		usage;
    const xmlChar			*href;

    xmlSecTransformCreateMethod		create;
    xmlSecTransformDestroyMethod	destroy;
    xmlSecTransformReadNodeMethod	read;
    
    /* xmlTransform info */
    xmlSecXmlTransformExecuteMethod	executeXml;
};

typedef struct _xmlSecXmlTransform {
    /* same as for xmlSecTransform but id type changed */
    xmlSecXmlTransformId		id;
    xmlSecTransformStatus		status;
    int					dontDestroy;
    void				*data;
    
    /* xmlSecXmlTransform specific */
    xmlNodePtr				here;
    void				*xmlData;
} xmlSecXmlTransform;

/**
 * C14N Transform
 */
typedef int 	(*xmlSecC14NTransformExecuteMethod)	(xmlSecC14NTransformPtr transform,
							 xmlDocPtr doc,
							 xmlNodeSetPtr nodes,
							 xmlOutputBufferPtr buffer);
typedef const struct _xmlSecC14NTransformId	*xmlSecC14NTransformId;
struct _xmlSecC14NTransformId {
    /* same as xmlSecTransformId */ 
    xmlSecTransformType			type;
    xmlSecTransformUsage		usage;
    const xmlChar			*href;

    xmlSecTransformCreateMethod		create;
    xmlSecTransformDestroyMethod	destroy;
    xmlSecTransformReadNodeMethod	read;
    
    /* xmlC14nTransform specific */
    xmlSecC14NTransformExecuteMethod	executeC14N;
};

typedef struct _xmlSecC14NTransform {
    /* same as for xmlSecTransform but id type changed */
    xmlSecC14NTransformId		id;
    xmlSecTransformStatus		status;
    int					dontDestroy;
    void				*data;
    
    /* xmlSecC14NTransform specific */ 
    void				*c14nData;
} xmlSecC14NTransform;


/**
 * Transforms State
 */
typedef struct _xmlSecTransformState {
    /* initial state */
    xmlDocPtr				initDoc;
    xmlNodeSetPtr			initNodeSet;
    char				*initUri;

    /* current state: xml */    
    xmlDocPtr				curDoc;
    xmlNodeSetPtr			curNodeSet;
    
    /* current state: binary */
    xmlBufferPtr			curBuf;
    xmlSecTransformPtr			curFirstBinTransform;
    xmlSecTransformPtr			curLastBinTransform;
    /*  optimization: special case for c14n transforms */
    xmlSecTransformPtr			curC14NTransform; 
} xmlSecTransformState;


/** 
 * Hi-level functions
 */
void 			xmlSecTransformsInit		(void);
int			xmlSecTransformsNodeRead	(xmlSecTransformStatePtr state, 
							 xmlNodePtr transformsNode);
xmlSecTransformId	xmlSecTransformFind		(const xmlChar *href);
xmlSecTransformPtr	xmlSecTransformNodeRead		(xmlNodePtr transformNode, 
							 xmlSecTransformUsage usage,
							 int dontDestroy);
int			xmlSecTransformNodeWrite	(xmlNodePtr transformNode,
							 xmlSecTransformId id);
/**
 * Transform 
 */ 
#define xmlSecTransformIsValid(transform) \
	((( transform ) != NULL) && ((( transform )->id) != NULL))
#define xmlSecTransformCheckType(transform, t) \
 	(xmlSecTransformIsValid(( transform )) && \
	((( transform )->id->type) == ( t )))
#define xmlSecTransformCheckId(transform, i) \
 	(xmlSecTransformIsValid(( transform )) && \
	((((const xmlSecTransformId) (( transform )->id))) == ( i )))

xmlSecTransformPtr	xmlSecTransformCreate		(xmlSecTransformId id,
							 xmlSecTransformUsage usage,
							 int dontDestroy);
void			xmlSecTransformDestroy		(xmlSecTransformPtr transform,
							 int forceDestroy);
int 			xmlSecTransformRead		(xmlSecTransformPtr transform,
							 xmlNodePtr transformNode);

/**
 * Binary transform
 */ 
#define xmlSecBinTransformIdCheckKeyId(id, kId) \
	(((id) != NULL) && \
	 ((id)->type == xmlSecTransformTypeBinary) && \
	 (((xmlSecBinTransformId)(id))->keyId == kId))
#define xmlSecBinTransformIdGetKeyId(id) \
	((((id) != NULL) && \
	 ((id)->type == xmlSecTransformTypeBinary)) ? \
	  ((xmlSecBinTransformId)(id))->keyId : \
	  xmlSecKeyIdUnknown)
#define xmlSecBinTransformCheckSubType(transform, t) \
	(xmlSecTransformCheckType(( transform ), xmlSecTransformTypeBinary) && \
	((((xmlSecBinTransformId)(( transform )->id))->binSubType) == ( t )))
#define xmlSecBinTransformIdGetEncKeyType(id) \
	((((id) != NULL) && \
	 ((id)->type == xmlSecTransformTypeBinary)) ? \
	  ((xmlSecBinTransformId)(id))->encryption : \
	  xmlSecKeyTypeAny)
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
/** 
 * XML Transform
 */
int 			xmlSecXmlTransformExecute	(xmlSecTransformPtr transform,
							 xmlDocPtr ctxDoc,
							 xmlDocPtr *doc,
							 xmlNodeSetPtr *nodes);
void			xmlSecXmlTransformSetHere	(xmlSecTransformPtr trasnform,
							 xmlNodePtr here);
							 
/**
 * C14N Transform
 */ 
int 			xmlSecC14NTransformExecute	(xmlSecTransformPtr transform,
							 xmlDocPtr doc,
							 xmlNodeSetPtr nodes,
							 xmlOutputBufferPtr buffer);
/**
 * Transforms State
 */
xmlSecTransformStatePtr	xmlSecTransformStateCreate	(xmlDocPtr doc,
							 xmlNodeSetPtr nodeSet,
							 const char *uri);
void			xmlSecTransformStateDestroy	(xmlSecTransformStatePtr state);
int			xmlSecTransformStateUpdate	(xmlSecTransformStatePtr state,
							 xmlSecTransformPtr transform);
int			xmlSecTransformStateFinal	(xmlSecTransformStatePtr state,
							 xmlSecTransformResult type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_TRANSFORMS_INTERNAL_H__ */

