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

typedef enum {
    xmlEncCtxModeEncryptedData = 0,
    xmlEncCtxModeEncryptedKey
} xmlEncCtxMode;

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
    void*			userData;
    xmlEncCtxMode		mode;
    xmlSecKeyInfoCtx		keyInfoReadCtx;
    xmlSecKeyInfoCtx		keyInfoWriteCtx;
    xmlSecTransformCtx		encTransformCtx;

    xmlSecTransformPtr		encMethod;
    xmlSecKeyPtr		encKey;

    /* these data are returned */
    xmlSecBufferPtr		result;
    xmlSecTransformOperation	operation;
    int				resultBase64Encoded;
    int				resultReplaced;

    /* attributes from EncryptedData or EncryptedKey */    
    xmlChar*			id;
    xmlChar*			type;
    xmlChar*			mimeType;
    xmlChar*			encoding;
    xmlChar*			recipient;
    xmlChar*			carriedKeyName;

    /* these are internal data, nobody should change that except us */
    int				dontDestroyEncMethod;
    xmlNodePtr			encDataNode;
    xmlNodePtr			encMethodNode;
    xmlNodePtr			keyInfoNode;
    xmlNodePtr			cipherValueNode;
    
    /* reserved for future */
    void*			reserved0;
    void*			reserved1;
};

XMLSEC_EXPORT xmlSecEncCtxPtr	xmlSecEncCtxCreate		(xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void 		xmlSecEncCtxDestroy		(xmlSecEncCtxPtr encCtx);
XMLSEC_EXPORT int		xmlSecEncCtxInitialize		(xmlSecEncCtxPtr encCtx,
								 xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void		xmlSecEncCtxFinalize		(xmlSecEncCtxPtr encCtx);
XMLSEC_EXPORT int		xmlSecEncCtxBinaryEncrypt	(xmlSecEncCtxPtr encCtx,
								 xmlNodePtr tmpl,
								 const unsigned char* data,
								 size_t dataSize);
XMLSEC_EXPORT int		xmlSecEncCtxXmlEncrypt		(xmlSecEncCtxPtr encCtx,
								 xmlNodePtr tmpl,
								 xmlNodePtr node);
XMLSEC_EXPORT int		xmlSecEncCtxUriEncrypt		(xmlSecEncCtxPtr encCtx,
								 xmlNodePtr tmpl,
								 const xmlChar *uri);
XMLSEC_EXPORT int		xmlSecEncCtxDecrypt		(xmlSecEncCtxPtr encCtx,
								 xmlNodePtr node);
XMLSEC_EXPORT xmlSecBufferPtr	xmlSecEncCtxDecryptToBuffer	(xmlSecEncCtxPtr encCtx,
								 xmlNodePtr node		);
XMLSEC_EXPORT void		xmlSecEncCtxDebugDump		(xmlSecEncCtxPtr encCtx,
								 FILE* output);
XMLSEC_EXPORT void		xmlSecEncCtxDebugXmlDump	(xmlSecEncCtxPtr encCtx,
								 FILE* output);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NO_XMLENC */

#endif /* __XMLSEC_XMLENC_H__ */

