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

/**
 * xmlSecEncTypeElement:
 * 
 * The element node is encrypted.
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecEncTypeElement[];

/**
 * xmlSecEncTypeContent:
 *
 * The element node content is encrypted.
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecEncTypeContent[]; 

typedef struct _xmlSecEncCtx xmlSecEncCtx, *xmlSecEncCtxPtr; 
typedef struct _xmlSecEncResult xmlSecEncResult, *xmlSecEncResultPtr; 


/** 
 * xmlSecEncCtx:
 * @keysMngr: the pointer to keys manager #xmlSecKeysMngr.
 * @encryptionMethod: the default encryption algorithm id.
 * @ignoreType:	the flag to ignore Type attribute in the <enc:EncryptedData> 
 * 	node
 *
 * XML Encrypiton context.
 */
struct _xmlSecEncCtx {
    xmlSecKeysMngrPtr		keysMngr;
    xmlSecTransformId		encryptionMethod;
    int				ignoreType;
};

/**
 * xmlSecEncResult:
 * @ctx: the pointer to #xmlSecEncCtx structure.
 * @context: the pointer to application specific data.
 * @self: the pointer to  <enc:EncryptedData> node.
 * @encrypt: the encrypt/decrypt flag.
 * @id: the Id attribute of the  <enc:EncryptedData> node.
 * @type: the Type attribute of the  <enc:EncryptedData> node.
 * @mimeType: the MimeType attribute of the  <enc:EncryptedData> node.
 * @encoding: the Encoding attribute of the  <enc:EncryptedData> node.
 * @encryptionMethod: the used encryption algorithm id.
 * @key: the used encryption key.
 * @buffer: the decrypted data.
 * @replaced: if set then the decrypted data were put back into the original document.
 *
 * The XML Encrypiton results.
 */
struct _xmlSecEncResult {
    xmlSecEncCtxPtr		ctx;
    void			*context;
    xmlNodePtr			self;
    int				encrypt;
    xmlChar			*id;
    xmlChar			*type;
    xmlChar			*mimeType;
    xmlChar			*encoding;
    xmlSecTransformId		encryptionMethod;
    xmlSecKeyPtr		key;
    xmlBufferPtr		buffer;
    int				replaced;
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

