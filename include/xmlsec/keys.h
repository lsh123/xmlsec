/** 
 * XMLSec library
 *
 * Keys Base: forward declarations
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_KEYS_H__
#define __XMLSEC_KEYS_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 


#include <xmlsec/xmlsec.h>
#include <xmlsec/list.h>
#include <xmlsec/keysdata.h>


/**
 * xmlSecKeyUsage:
 * @xmlSecKeyUsageAny: the key can be used in any way.
 * @xmlSecKeyUsageSign: the key for signing.
 * @xmlSecKeyUsageVerify: the key for signature verification.
 * @xmlSecKeyUsageEncrypt: the encryption key.
 * @xmlSecKeyUsageDecrypt: the decryption key.
 *
 * The key usage.
 */
typedef enum  {
    xmlSecKeyUsageAny = 0,
    xmlSecKeyUsageSign,
    xmlSecKeyUsageVerify,
    xmlSecKeyUsageEncrypt,
    xmlSecKeyUsageDecrypt
} xmlSecKeyUsage;


/**************************************************************************
 *
 * xmlSecKeyReq - what key are we looking for?
 *
 *************************************************************************/
typedef struct _xmlSecKeyReq 			xmlSecKeyReq, *xmlSecKeyReqPtr; 
struct _xmlSecKeyReq {
    xmlSecKeyDataId			keyId;
    xmlSecKeyDataType			keyType;
    xmlSecKeyUsage			keyUsage;
    size_t				keyBitsSize;
};

XMLSEC_EXPORT int	xmlSecKeyReqInitialize			(xmlSecKeyReqPtr keyReq);
XMLSEC_EXPORT void	xmlSecKeyReqFinalize			(xmlSecKeyReqPtr keyReq);
XMLSEC_EXPORT int	xmlSecKeyReqCopy			(xmlSecKeyReqPtr dst,
								 xmlSecKeyReqPtr src);
XMLSEC_EXPORT int	xmlSecKeyReqMatchKey			(xmlSecKeyReqPtr keyReq,
								 xmlSecKeyPtr key);
XMLSEC_EXPORT int	xmlSecKeyReqMatchKeyValue		(xmlSecKeyReqPtr keyReq,
								 xmlSecKeyDataPtr value);

/**
 * xmlSecKey:
 * @origin: the key origin.
 * @keyData: key specific data.
 *
 * The key.
 */
struct _xmlSecKey {
    xmlSecKeyDataPtr			value;
    xmlChar*				name;
    xmlSecPtrListPtr			dataList;

    /* for the future */
    void*				reserved0;
    void*				reserved1;
};

XMLSEC_EXPORT xmlSecKeyPtr	xmlSecKeyCreate		(void);
XMLSEC_EXPORT void		xmlSecKeyDestroy	(xmlSecKeyPtr key);
XMLSEC_EXPORT void		xmlSecKeyEmpty		(xmlSecKeyPtr key);
XMLSEC_EXPORT xmlSecKeyPtr	xmlSecKeyDuplicate	(xmlSecKeyPtr key);
XMLSEC_EXPORT int		xmlSecKeyCopy		(xmlSecKeyPtr keyDst,
							 xmlSecKeyPtr keySrc);

XMLSEC_EXPORT const xmlChar*	xmlSecKeyGetName	(xmlSecKeyPtr key);
XMLSEC_EXPORT int		xmlSecKeySetName	(xmlSecKeyPtr key,
							 const xmlChar* name);

XMLSEC_EXPORT xmlSecKeyDataType	xmlSecKeyGetType	(xmlSecKeyPtr key);

XMLSEC_EXPORT xmlSecKeyDataPtr	xmlSecKeyGetValue	(xmlSecKeyPtr key);
XMLSEC_EXPORT int		xmlSecKeySetValue	(xmlSecKeyPtr key,
							 xmlSecKeyDataPtr value);

XMLSEC_EXPORT xmlSecKeyDataPtr 	xmlSecKeyGetData	(xmlSecKeyPtr key, 
							 xmlSecKeyDataId dataId);
XMLSEC_EXPORT xmlSecKeyDataPtr 	xmlSecKeyEnsureData	(xmlSecKeyPtr key, 
							 xmlSecKeyDataId dataId);
XMLSEC_EXPORT int		xmlSecKeyAdoptData	(xmlSecKeyPtr key,
							 xmlSecKeyDataPtr data);

XMLSEC_EXPORT void		xmlSecKeyDebugDump	(xmlSecKeyPtr key,
							 FILE *output);
XMLSEC_EXPORT void		xmlSecKeyDebugXmlDump	(xmlSecKeyPtr key,
							 FILE *output);


XMLSEC_EXPORT xmlSecKeyPtr	xmlSecKeyGenerate	(const xmlChar* klass,
							 const xmlChar* name,
							 size_t sizeBits,
							 xmlSecKeyDataType type);


XMLSEC_EXPORT int		xmlSecKeyMatch		(xmlSecKeyPtr key, 
							 const xmlChar *name,
							 xmlSecKeyReqPtr keyReq);
							 
/**
 * xmlSecKeyIsValid:
 * @key: the pointer to key.
 *
 * Macro. Returns 1 if @key is not NULL and @key->id is not NULL
 * or 0 otherwise.
 */ 
#define xmlSecKeyIsValid(key) \
	((( key ) != NULL) && \
	 (( key )->value != NULL) && \
	 ((( key )->value->id) != NULL))
/**
 * xmlSecKeyCheckId:
 * @key: the pointer to key.
 * @keyId: the key Id.
 *
 * Macro. Returns 1 if @key is valid and @key's id is equal to @keyId.
 */
#define xmlSecKeyCheckId(key, keyId) \
 	(xmlSecKeyIsValid(( key )) && \
	((( key )->value->id) == ( keyId )))


/***********************************************************************
 *
 * Keys list
 *
 **********************************************************************/
#define xmlSecKeyPtrListId	xmlSecKeyPtrListGetKlass()
XMLSEC_EXPORT xmlSecPtrListId	xmlSecKeyPtrListGetKlass		(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYS_H__ */

