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
#include <xmlsec/buffer.h>
#include <xmlsec/transforms.h>

typedef struct _xmlSecEncCtx 	xmlSecEncCtx, *xmlSecEncCtxPtr; 


/** 
 * xmlSecEncCtx:
 * @self: the pointer to  <enc:EncryptedData> node.
 * @id: the Id attribute of the  <enc:EncryptedData> node.
 * @type: the Type attribute of the  <enc:EncryptedData> node.
 * @mimeType: the MimeType attribute of the  <enc:EncryptedData> node.
 * @encoding: the Encoding attribute of the  <enc:EncryptedData> node.
 * @encryptionMethod: the used encryption algorithm id.
 * @encryptionKey: the used encryption key.
 * @encryptionResult: the encrypted or decrypted data.


 * @keysMngr: the pointer to keys manager #xmlSecKeysMngr.
 * @ignoreType:	the flag to ignore Type attribute in the <enc:EncryptedData> 
 * 	node
 *
 * XML Encrypiton context.
 */
struct _xmlSecEncCtx {
    /* these data user can set before performing the operation */
    void*			userCtx;
    xmlSecKeyInfoCtx		keyInfoCtx;
    xmlSecTransformCtx		transformCtx;
    xmlSecTransformPtr		defEncMethod;
    xmlSecKeyPtr		encKey;

    /* these data are returned */
    xmlChar			*id;
    xmlChar			*type;
    xmlChar			*mimeType;
    xmlChar			*encoding;
    int				encrypt;
    xmlSecTransformPtr		encMethod;
    xmlSecBufferPtr		encResult;
    int				replaced;

    /* these are internal data, nobody cares about that */
    xmlNodePtr			encDataNode;
    xmlNodePtr			encMethodNode;
    xmlNodePtr			keyInfoNode;
    xmlNodePtr			cipherValueNode;
};

XMLSEC_EXPORT xmlSecEncCtxPtr	xmlSecEncCtxCreate		(xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void 		xmlSecEncCtxDestroy		(xmlSecEncCtxPtr ctx);
XMLSEC_EXPORT int		xmlSecEncCtxInitialize		(xmlSecEncCtxPtr ctx,
								 xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void		xmlSecEncCtxFinalize		(xmlSecEncCtxPtr ctx);
XMLSEC_EXPORT int		xmlSecEncCtxEncryptUri		(xmlSecEncCtxPtr ctx,
								 xmlNodePtr node,
								 const xmlChar *uri);
XMLSEC_EXPORT int		xmlSecEncCtxDecrypt		(xmlSecEncCtxPtr ctx,
								 xmlNodePtr node);
XMLSEC_EXPORT xmlSecBufferPtr	xmlSecEncCtxDecryptToBuffer	(xmlSecEncCtxPtr ctx,
								 xmlNodePtr node);
XMLSEC_EXPORT void		xmlSecEncCtxDebugDump		(xmlSecEncCtxPtr ctx,
								 FILE* output);
XMLSEC_EXPORT void		xmlSecEncCtxDebugXmlDump	(xmlSecEncCtxPtr ctx,
								 FILE* output);


#include <xmlsec/xmlenc-old.h>

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NO_XMLENC */

#endif /* __XMLSEC_XMLENC_H__ */

