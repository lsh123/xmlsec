/** 
 * XMLSec library
 *
 * KeyInfo node processing
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_KEYINFO_H__
#define __XMLSEC_KEYINFO_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <time.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/list.h>
#include <xmlsec/keysdata.h>
#include <xmlsec/keys.h>

/**
 * Hi level functions
 */
XMLSEC_EXPORT int	 	xmlSecKeyInfoNodeRead		(xmlNodePtr keyInfoNode,
								 xmlSecKeyPtr key,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int 		xmlSecKeyInfoNodeWrite		(xmlNodePtr keyInfoNode,
								 xmlSecKeyPtr key,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);

/**
 * xmlSecKeyInfoCtx:
 *
 * TODO
 */
struct _xmlSecKeyInfoCtx {
    void*				userData;
    xmlSecKeysMngrPtr			keysMngr;
    int					base64LineSize;
    xmlSecPtrListPtr			allowedKeyDataIds;
    
    /* RetrievalMethod */
    xmlSecTransformCtxPtr		transformCtx;
    int 				retrievalsLevel;

    /* EncryptedKey */
    xmlSecEncCtxPtr			encCtx;
    int					encKeysLevel;                

    /* x509 certificates */
    int					failIfCertNotFound;
    time_t				certsVerificationTime;
    int					certsVerificationDepth;
    
    /* internal data */
    xmlSecKeyReq			keyReq;
};

XMLSEC_EXPORT xmlSecKeyInfoCtxPtr 	xmlSecKeyInfoCtxCreate		(xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void			xmlSecKeyInfoCtxDestroy		(xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int			xmlSecKeyInfoCtxInitialize	(xmlSecKeyInfoCtxPtr keyInfoCtx,
									 xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void			xmlSecKeyInfoCtxFinalize	(xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int 			xmlSecKeyInfoCtxCreateEncCtx	(xmlSecKeyInfoCtxPtr keyInfoCtx);
XMLSEC_EXPORT int			xmlSecKeyInfoCtxCopyUserPref	(xmlSecKeyInfoCtxPtr dst,
									 xmlSecKeyInfoCtxPtr src);
XMLSEC_EXPORT int			xmlSecKeyInfoCtxEnableKeyData	(xmlSecKeyInfoCtxPtr keyInfoCtx,
									 xmlSecKeyDataId dataId);
XMLSEC_EXPORT int			xmlSecKeyInfoCtxEnableKeyDataByName(xmlSecKeyInfoCtxPtr keyInfoCtx,
									 const xmlChar* name);


#define xmlSecKeyInfoNodeCheckOrigin(status, origin) \
	( ( ((status) != NULL) && \
	    ((status)->keysMngr != NULL) && \
	    ((status)->keysMngr->allowedOrigins & origin) ) ? \
	    1 : 0 )
#define xmlSecKeyInfoNodeCheckRetrievalsLevel(status) \
	( ( ((status) != NULL) && \
	    ((status)->keysMngr != NULL) && \
	    ((status)->keysMngr->maxRetrievalsLevel >= 0) ) ? \
	    ((status)->keysMngr->maxRetrievalsLevel >= (status)->retrievalsLevel) : \
	    1 )
#define xmlSecKeyInfoNodeCheckEncKeysLevel(status) \
	( ( ((status) != NULL) && \
	    ((status)->keysMngr != NULL) && \
	    ((status)->keysMngr->maxEncKeysLevel >= 0) ) ? \
	    ((status)->keysMngr->maxEncKeysLevel >= (status)->encKeysLevel) : \
	    1 )

/**
 * xmlSecKeyDataNameId
 *
 * The <dsig:KeyName> processing class.
 */
#define xmlSecKeyDataNameId	xmlSecKeyDataNameGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId	xmlSecKeyDataNameGetKlass		(void);

/**
	 * xmlSecKeyDataValueId
 *
 * The <dsig:KeyValue> processing class.
 */
#define xmlSecKeyDataValueId	xmlSecKeyDataValueGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId	xmlSecKeyDataValueGetKlass		(void);

/**
 * xmlSecKeyDataRetrievalMethodId
 *
 * The <dsig:RetrievalMethod> processing class.
 */
#define xmlSecKeyDataRetrievalMethodId	xmlSecKeyDataRetrievalMethodGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId	xmlSecKeyDataRetrievalMethodGetKlass	(void);

#ifndef XMLSEC_NO_XMLENC
/**
 * xmlSecKeyDataEncryptedKeyId
 *
 * The <enc:EncryptedKey> processing class.
 */
#define xmlSecKeyDataEncryptedKeyId	xmlSecKeyDataEncryptedKeyGetKlass()
XMLSEC_EXPORT xmlSecKeyDataId	xmlSecKeyDataEncryptedKeyGetKlass	(void);
#endif /* XMLSEC_NO_XMLENC */


		    
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KEYINFO_H__ */

