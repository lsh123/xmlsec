/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_OPENSSL_EVP_H__
#define __XMLSEC_OPENSSL_EVP_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <openssl/evp.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/ciphers.h>
#include <xmlsec/keys.h>

typedef struct _xmlSecEvpCipherTransform 	xmlSecEvpCipherTransform, *xmlSecEvpCipherTransformPtr; 
    /**
 * xmlSecEvpCipherTransform:
 * @id: the transform id (pointer to #xmlSecBinTransformId).
 * @status: the transform status (ok/fail/unknown).
 * @dontDestroy: the don't automatically destroy flag.
 * @data: the pointer to transform specific data.
 * @encode: encode/decode (encrypt/decrypt) flag.
 * @next: next binary transform in the chain.
 * @prev: previous binary transform in the chain.
 * @binData: the pointer to binary transform speific data.
 * @bufIn: the pointer to input buffer.
 * @bufOut: the pointer to output buffer.
 * @cipherCtx: the EVP chiper context.
 * @iv: the pointer to IV.
 * @ivPos:the position in IV (what was written out).
 * @cipherData: the chipher specific data.
 *
 * The cipher (encrypt/decrypt) transform.
 */
struct _xmlSecEvpCipherTransform {	
    /* same as for xmlSecTransform but id type changed */
    xmlSecCipherTransformId		id;    
    xmlSecTransformStatus		status;
    int					dontDestroy;
    void				*data;
    
    /* xmlSecBinTransform specific */
    int					encode;
    xmlSecCipherTransformPtr		next;
    xmlSecCipherTransformPtr		prev;   
    void				*binData;
    
    /* xmlSecCipherTransform specific */
    unsigned char			*bufIn;
    unsigned char			*bufOut;
    unsigned char			*iv;
    size_t				ivPos;
    void				*cipherData;
    
    /* xmlSecEvpCipherTransform specific */
    EVP_CIPHER_CTX 			cipherCtx;
};
 
/**
 * EVP Cipher Transform methods
 */
XMLSEC_EXPORT int 	xmlSecEvpCipherGenerateIv	(xmlSecCipherTransformPtr cipher);
XMLSEC_EXPORT int 	xmlSecEvpCipherInit		(xmlSecCipherTransformPtr cipher);
XMLSEC_EXPORT int 	xmlSecEvpCipherUpdate		(xmlSecCipherTransformPtr cipher,
							 const unsigned char *buffer,
							 size_t size);
XMLSEC_EXPORT int 	xmlSecEvpCipherFinal		(xmlSecCipherTransformPtr cipher);


/**
 * Misc EVP functions
 */
xmlSecKeyPtr		xmlSecEvpParseKey		(EVP_PKEY *pKey);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_OPENSSL_EVP_H__ */


