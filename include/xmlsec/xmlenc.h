/** 
 * XMLSec library
 *
 * "XML Encryption" implementation
 *  http://www.w3.org/TR/xmlenc-core
 * 
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_XMLENC_H__
#define __XMLSEC_XMLENC_H__    

#ifndef XMLSEC_NO_XMLENC

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 
#include <stdio.h>

#include <libxml/tree.h>
#include <libxml/parser.h> 

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>


typedef struct _xmlSecEncCtx xmlSecEncCtx, *xmlSecEncCtxPtr; 
typedef struct _xmlSecEncResult xmlSecEncResult, *xmlSecEncResultPtr; 

/**
 * xmlSecEncTypeElement:
 *
 * The element node is encrypted.
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecEncTypeElement[]; /* "http://www.w3.org/2001/04/xmlenc#Element"; */
/**
 * xmlSecEncTypeContent:
 *
 * The element node content is encrypted.
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecEncTypeContent[]; /* "http://www.w3.org/2001/04/xmlenc#Content"; */

/** 
 * struct _xmlSecEncCtx:
 *
 * XML Encrypiton context.
 */
struct _xmlSecEncCtx {
    xmlSecKeysMngrPtr		keysMngr;	/* the pointer to keys manager */
    xmlSecTransformId		encryptionMethod; /* the default encryption algorithm id */
    int				ignoreType;	/* the flag to ignore Type attribute 
						 in the <enc:EncryptedData> node */
};

/**
 * struct _xmlSecEncResult:
 *
 * The XML Encrypiton results.
 */
struct _xmlSecEncResult {
    xmlSecEncCtxPtr		ctx;		/* the pointer to #xmlSecEncCtx structure */
    void			*context;	/* the pointer to application specific data */
    xmlNodePtr			self;		/* the pointer to  <enc:EncryptedData> node */
    int				encrypt;	/* the encrypt/decrypt flag */
    xmlChar			*id;		/* the Id attribute of the  <enc:EncryptedData> node */
    xmlChar			*type;		/* the Type attribute of the  <enc:EncryptedData> node */
    xmlChar			*mimeType;	/* the MimeType attribute of the  <enc:EncryptedData> node */
    xmlChar			*encoding;    	/* the Encoding attribute of the  <enc:EncryptedData> node */
    xmlSecTransformId		encryptionMethod; /* the used encryption algorithm id */
    xmlSecKeyPtr		key;            /* the used encryption key */
    xmlBufferPtr		buffer;		/* the decrypted data */
    int				replaced;	/* if set then the decrypted data were put back 
						   into the original document */
};

/**
 * XML Encrypiton context methods
 */
XMLSEC_EXPORT xmlSecEncCtxPtr	xmlSecEncCtxCreate	(xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void 		xmlSecEncCtxDestroy	(xmlSecEncCtxPtr ctx);


/**
 * Encryption
 */
XMLSEC_EXPORT int		xmlSecEncryptMemory	(xmlSecEncCtxPtr ctx,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlNodePtr encNode,
							 const unsigned char *buf,
							 size_t size,
							 xmlSecEncResultPtr *result);
XMLSEC_EXPORT int		xmlSecEncryptUri	(xmlSecEncCtxPtr ctx,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlNodePtr encNode,
							 const char *uri,
							 xmlSecEncResultPtr *result);
XMLSEC_EXPORT int		xmlSecEncryptXmlNode	(xmlSecEncCtxPtr ctx,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlNodePtr encNode,
							 xmlNodePtr src,
							 xmlSecEncResultPtr *result);
/**
 * Decryption
 */
XMLSEC_EXPORT int		xmlSecDecrypt		(xmlSecEncCtxPtr ctx,
							 void *context,
							 xmlSecKeyPtr key,
							 xmlNodePtr encNode,
							 xmlSecEncResultPtr *result);
/**
 * XML Enc Result
 */		
XMLSEC_EXPORT xmlSecEncResultPtr xmlSecEncResultCreate	(xmlSecEncCtxPtr ctx,
							 void *context,
							 int encrypt,
							 xmlNodePtr node);
XMLSEC_EXPORT void 		xmlSecEncResultDestroy	(xmlSecEncResultPtr result);
XMLSEC_EXPORT void		xmlSecEncResultDebugDump(xmlSecEncResultPtr result,
							 FILE *output);

/** 
 * Encryption Template
 */
XMLSEC_EXPORT xmlNodePtr	xmlSecEncDataCreate	(const xmlChar *id,
							 const xmlChar *type,
							 const xmlChar *mimeType,
							 const xmlChar *encoding);
XMLSEC_EXPORT void 		xmlSecEncDataDestroy	(xmlNodePtr encNode);
XMLSEC_EXPORT xmlNodePtr	xmlSecEncDataAddEncMethod(xmlNodePtr encNode,
							 xmlSecTransformId encMethod);
XMLSEC_EXPORT xmlNodePtr	xmlSecEncDataAddKeyInfo	(xmlNodePtr encNode);							 
XMLSEC_EXPORT xmlNodePtr	xmlSecEncDataAddEncProperties	
							(xmlNodePtr encNode,
							 const xmlChar *id); 
XMLSEC_EXPORT xmlNodePtr	xmlSecEncDataAddEncProperty	
							(xmlNodePtr encNode,
							 const xmlChar *id,
							 const xmlChar *target);
XMLSEC_EXPORT xmlNodePtr	xmlSecEncDataAddCipherValue		
							(xmlNodePtr encNode);
XMLSEC_EXPORT xmlNodePtr	xmlSecEncDataAddCipherReference	
							(xmlNodePtr encNode,
							 const xmlChar *uri);
XMLSEC_EXPORT xmlNodePtr	xmlSecCipherReferenceAddTransform(xmlNodePtr encNode,
							 xmlSecTransformId transform);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NO_XMLENC */

#endif /* __XMLSEC_XMLENC_H__ */

