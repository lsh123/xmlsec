	/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * "XML Key Management Specification v 2.0" implementation
 *  http://www.w3.org/TR/xkms2/
 * 
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_XKMS_H__
#define __XMLSEC_XKMS_H__    

#ifndef XMLSEC_NO_XKMS
	
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 
#include <stdio.h>		

#include <libxml/tree.h>
#include <libxml/parser.h> 

#include <xmlsec/xmlsec.h>
#include <xmlsec/buffer.h>
#include <xmlsec/list.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>

typedef struct _xmlSecXkmsRespondWithKlass	xmlSecXkmsRespondWithKlass, 
						*xmlSecXkmsRespondWithId;

typedef struct _xmlSecXkmsServerRequestKlass	xmlSecXkmsServerRequestKlass, 
						*xmlSecXkmsServerRequestId;

/************************************************************************
 *
 * XKMS requests server side processing klass
 *
 ************************************************************************/ 
/**
 * XMLSEC_XKMS_NO_RESPONSE_LIMIT:
 *
 * The responseLimit value.
 */
#define XMLSEC_XKMS_NO_RESPONSE_LIMIT				-1

/** 
 * xmlSecXkmsServerCtx:
 * @userData:			the pointer to user data (xmlsec and xmlsec-crypto libraries
 *				never touches this).
 * @flags:			the XML Encryption processing flags.
 * @flags2:			the XML Encryption processing flags.
 * @keyInfoReadCtx:		the reading key context.
 * @keyInfoWriteCtx:		the writing key context (not used for signature verification).
 * @reserved0:			reserved for the future.
 * @reserved1:			reserved for the future.
 * 
 * XKMS context.
 */
struct _xmlSecXkmsServerCtx {
    /* these data user can set before performing the operation */
    void*			userData;
    unsigned int		flags;
    unsigned int		flags2;    
    xmlSecKeyInfoCtx		keyInfoReadCtx;
    xmlSecKeyInfoCtx		keyInfoWriteCtx;
    xmlSecPtrList		enabledRespondWithIds;
    xmlSecPtrList		enabledServerRequestIds;
    xmlChar* 			expectedService;
        
    /* these data are returned */
    xmlSecPtrList		keys;
    int				majorError;
    int				minorError;
    xmlSecXkmsServerRequestId	requestId;
    xmlChar*			id;    
    xmlChar*			service;
    xmlChar*			nonce;
    xmlChar*			originalRequestId;
    xmlChar*                    pendingNotificationMechanism;
    xmlChar*                    pendingNotificationIdentifier;
    int 			responseLimit;
    xmlSecBitMask		responseMechanismMask;
    xmlSecPtrListPtr		compoundRequestContexts;

    /* these are internal data, nobody should change that except us */
    xmlNodePtr			opaqueClientDataNode;
    xmlNodePtr 			firtsMsgExtNode;
    xmlNodePtr 			keyInfoNode;
    xmlSecPtrList		respWithList;
    
    /* reserved for future */
    void*			reserved0;
    void*			reserved1;
};

XMLSEC_EXPORT xmlSecXkmsServerCtxPtr	xmlSecXkmsServerCtxCreate(xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void 		xmlSecXkmsServerCtxDestroy	(xmlSecXkmsServerCtxPtr ctx);
XMLSEC_EXPORT int		xmlSecXkmsServerCtxInitialize	(xmlSecXkmsServerCtxPtr ctx,
								 xmlSecKeysMngrPtr keysMngr);
XMLSEC_EXPORT void		xmlSecXkmsServerCtxFinalize	(xmlSecXkmsServerCtxPtr ctx);
XMLSEC_EXPORT int		xmlSecXkmsServerCtxCopyUserPref(xmlSecXkmsServerCtxPtr dst,
								 xmlSecXkmsServerCtxPtr src);
XMLSEC_EXPORT void		xmlSecXkmsServerCtxReset	(xmlSecXkmsServerCtxPtr ctx);
XMLSEC_EXPORT void		xmlSecXkmsServerCtxSetError	(xmlSecXkmsServerCtxPtr ctx,
								 int majorError,
								 int minorError);
XMLSEC_EXPORT int		xmlSecXkmsServerCtxRequestRead	(xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);
XMLSEC_EXPORT int		xmlSecXkmsServerCtxResponseWrite(xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr* node);
XMLSEC_EXPORT int		xmlSecXkmsServerCtxProcess	(xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr inNode,
								 xmlNodePtr* outNode);
XMLSEC_EXPORT void		xmlSecXkmsServerCtxDebugDump	(xmlSecXkmsServerCtxPtr ctx,
								 FILE* output);
XMLSEC_EXPORT void		xmlSecXkmsServerCtxDebugXmlDump(xmlSecXkmsServerCtxPtr ctx,
								 FILE* output);

/************************************************************************
 *
 * xmlSecXkmsServerCtxPtr list
 *
 ************************************************************************/ 
/**
 * xmlSecXkmsServerCtxPtrListId:
 *
 * zmlSecXkmsServerCtx klasses list klass.
 */
#define xmlSecXkmsServerCtxPtrListId	xmlSecXkmsServerCtxPtrListGetKlass()
XMLSEC_EXPORT xmlSecPtrListId	xmlSecXkmsServerCtxPtrListGetKlass(void);

/************************************************************************
 *
 * XKMS ResultMajor attribute values.
 *
 ************************************************************************/ 
/**
 * XMLSEC_XKMS_ERROR_MAJOR_SUCCESS:
 *
 * XKMS ResultMajor attribute value. The operation succeeded.
 */
#define XMLSEC_XKMS_ERROR_MAJOR_SUCCESS			0		

/**
 * XMLSEC_XKMS_ERROR_MAJOR_VERSION_MISMATCH:
 *
 * XKMS ResultMajor attribute value. The service does not support 
 * the protocol version specified in the request.
 */
#define XMLSEC_XKMS_ERROR_MAJOR_VERSION_MISMATCH	1	

/**
 * XMLSEC_XKMS_ERROR_MAJOR_SENDER:
 *
 * XKMS ResultMajor attribute value. An error occurred that was due to 
 * the message sent by the sender.
 */
#define XMLSEC_XKMS_ERROR_MAJOR_SENDER			2			

/**
 * XMLSEC_XKMS_ERROR_MAJOR_RECEIVER:
 *
 * XKMS ResultMajor attribute value. An error occurred at the receiver.
 */
#define XMLSEC_XKMS_ERROR_MAJOR_RECEIVER		3			

/**
 * XMLSEC_XKMS_ERROR_MAJOR_REPRESENT:
 *
 * XKMS ResultMajor attribute value. The service has not acted on 
 * the request. In order for the request to be acted upon the request MUST 
 * be represented with the specified nonce in accordance with the two phase 
 * protocol.
 */
#define XMLSEC_XKMS_ERROR_MAJOR_REPRESENT		4			

/**
 * XMLSEC_XKMS_ERROR_MAJOR_PENDING:
 *
 * XKMS ResultMajor attribute value. The request has been accepted 
 * for processing and the service will return the result asynchronously.
 */
#define XMLSEC_XKMS_ERROR_MAJOR_PENDING			5			

/************************************************************************
 *
 * XKMS ResultMinor attribute values.
 *
 ************************************************************************/ 
/**
 * XMLSEC_XKMS_ERROR_MINOR_NONE:
 *
 * XKMS ResultMinor attribute value. Not specified.
 */
#define XMLSEC_XKMS_ERROR_MINOR_NONE			0		

/**
 * XMLSEC_XKMS_ERROR_MINOR_NO_MATCH:
 *
 * XKMS ResultMinor attribute value. No match was found for the search 
 * prototype provided.
 */
#define XMLSEC_XKMS_ERROR_MINOR_NO_MATCH		1		

/**
 * XMLSEC_XKMS_ERROR_MINOR_TOO_MANY_RESPONSES:
 *
 * XKMS ResultMinor attribute value. The request resulted in the number of 
 * responses that exceeded either  the ResponseLimit value specified in 
 * the request or some other limit determined by the service. 
 * The service MAY either return a subset of the possible 
 * responses or none at all.
 */
#define XMLSEC_XKMS_ERROR_MINOR_TOO_MANY_RESPONSES	2		

/**
 * XMLSEC_XKMS_ERROR_MINOR_INCOMPLETE:
 *
 * XKMS ResultMinor attribute value. Only part of the information requested 
 * could be provided.
 */
#define XMLSEC_XKMS_ERROR_MINOR_INCOMPLETE		3

/**
 * XMLSEC_XKMS_ERROR_MINOR_FAILURE:
 *
 * XKMS ResultMinor attribute value. The service attempted to perform 
 * the request but the operation failed for unspecified reasons.
 */
#define XMLSEC_XKMS_ERROR_MINOR_FAILURE			4		

/**
 * XMLSEC_XKMS_ERROR_MINOR_REFUSED:
 *
 * XKMS ResultMinor attribute value. The operation was refused. The service 
 * did not attempt to perform the request.
 */
#define XMLSEC_XKMS_ERROR_MINOR_REFUSED			5		

/**
 * XMLSEC_XKMS_ERROR_MINOR_NO_AUTHENTICATION:
 *
 * XKMS ResultMinor attribute value. The operation was refused because 
 * the necessary authentication information was incorrect or missing.
 */
#define XMLSEC_XKMS_ERROR_MINOR_NO_AUTHENTICATION	6		

/**
 * XMLSEC_XKMS_ERROR_MINOR_MESSAGE_NOT_SUPPORTED:
 *	
 * XKMS ResultMinor attribute value. The receiver does not implement 
 * the specified operation.
 */
#define XMLSEC_XKMS_ERROR_MINOR_MESSAGE_NOT_SUPPORTED	7		

/**
 * XMLSEC_XKMS_ERROR_MINOR_UNKNOWN_RESPONSE_ID:
 *
 * XKMS ResultMinor attribute value. The ResponseId for which pending 
 * status was requested is unknown to the service.
 */
#define XMLSEC_XKMS_ERROR_MINOR_UNKNOWN_RESPONSE_ID	8		

/**
 * XMLSEC_XKMS_ERROR_MINOR_NOT_SYNCHRONOUS:
 *
 * XKMS ResultMinor attribute value. The receiver does not support 
 * synchronous processing of this type of request
 */
#define XMLSEC_XKMS_ERROR_MINOR_NOT_SYNCHRONOUS		9		


/************************************************************************
 *
 * XKMS ResponseMechanism element values.
 *
 ************************************************************************/ 
/**
 * XMLSEC_XKMS_RESPONSE_MECHANISM_MASK_REPRESENT:
 *
 * XKMS ResponseMechanism element value. The requestor is prepared to 
 * accept a response that uses asynchronous processing, i.e. the service 
 * MAY return the MajorResult code Pending.
 */
#define XMLSEC_XKMS_RESPONSE_MECHANISM_MASK_PENDING			0x00000001	

/**
 * XMLSEC_XKMS_RESPONSE_MECHANISM_MASK_REPRESENT:
 *
 * XKMS ResponseMechanism element value. The requestor is prepared to 
 * accept a response that uses the two phase protocol, i.e. the service 
 * MAY return the MajorResult code Represent.
 */
#define XMLSEC_XKMS_RESPONSE_MECHANISM_MASK_REPRESENT			0x00000002

/**
 * XMLSEC_XKMS_RESPONSE_MECHANISM_MASK_REQUEST_SIGNATURE_VALUE:
 *
 * XKMS ResponseMechanism element value. The requestor is prepared to 
 * accept a response that carries a <RequestSignatureValue> element.
 */
#define XMLSEC_XKMS_RESPONSE_MECHANISM_MASK_REQUEST_SIGNATURE_VALUE	0x00000004

/************************************************************************
 *
 * XKMS ResponseLimit element values
 *
 ************************************************************************/ 
/**
 * XMLSEC_XKMS_NO_RESPONSE_LIMIT:
 *
 * The ResponseLimit is not specified.
 */
#define XMLSEC_XKMS_NO_RESPONSE_LIMIT			-1

/************************************************************************
 *
 * XKMS KeyBinding Status attribute values
 *
 ************************************************************************/ 
/**
 * XMLSEC_XKMS_KEY_BINDING_STATUS_UNKNOWN:
 *
 * The status is not known.
 */
#define XMLSEC_XKMS_KEY_BINDING_STATUS_UNKNOWN		 0

/**
 * XMLSEC_XKMS_KEY_BINDING_STATUS_VALID:
 *
 * Key is valid.
 */
#define XMLSEC_XKMS_KEY_BINDING_STATUS_VALID		 1

/**
 * XMLSEC_XKMS_KEY_BINDING_STATUS_INVALID:
 *
 * Key is not valid.
 */
#define XMLSEC_XKMS_KEY_BINDING_STATUS_INVALID		 2

/**
 * XMLSEC_XKMS_KEY_BINDING_STATUS_INDETERMINATE:
 *
 * Status can't be determinated.
 */
#define XMLSEC_XKMS_KEY_BINDING_STATUS_INDETERMINATE	 3

/************************************************************************
 *
 * XKMS KeyBinding reason values
 *
 ************************************************************************/ 
/**
 * XMLSEC_XKMS_KEY_BINDING_REASON_MASK_ISSUER_TRAST:
 *
 * The issuer of the information on which the key binding is based is 
 * considered to be trustworthy by the XKMS service.
 *
 * X.509 Equivalents
 *   - Valid:	Certificate path anchored by trusted root successfully constructed.
 *   - Invalid:	Certificate path could not be constructed to a trusted root.
 */
#define XMLSEC_XKMS_KEY_BINDING_REASON_MASK_ISSUER_TRAST	0x00000001

/**
 * XMLSEC_XKMS_KEY_BINDING_REASON_MASK_REVOCATION_STATUS:
 *
 * The XKMS service has affirmatively verified the status of the 
 * key binding with an authoritative source
 *
 * X.509 Equivalents
 *   - Valid:	Certificate status validated using CRL or OCSP.
 *   - Invalid:	Certificate status returned revoked or suspended.
 */
#define XMLSEC_XKMS_KEY_BINDING_REASON_MASK_REVOCATION_STATUS	0x00000002

/**
 * XMLSEC_XKMS_KEY_BINDING_REASON_MASK_VALIDITY_INTERVAL:
 *
 * The requested time instant was within the validity interval of 
 * the key binding
 *
 * X.509 Equivalents
 *   - Valid:	The certificate chain was valid at the requested time instant.
 *   - Invalid:	The requested time instant was before or after the certificate 
 *              chain validity interval.
 */
#define XMLSEC_XKMS_KEY_BINDING_REASON_MASK_VALIDITY_INTERVAL	 0x00000004

/**
 * XMLSEC_XKMS_KEY_BINDING_REASON_MASK_SIGNATURE:
 *
 * Signature on signed data provided by the client in the <Keyinfo> element was 
 * successfully verified.
 *
 * X.509 Equivalents
 *   - Valid: 	Certificate Signature verified.
 *   - Invalid: Certificate Signature verification failed.
 */
#define XMLSEC_XKMS_KEY_BINDING_REASON_MASK_SIGNATURE		 0x00000008


/************************************************************************
 *
 * XKMS RespondWith Klass
 *
 ************************************************************************/ 
XMLSEC_EXPORT xmlSecPtrListPtr	xmlSecXkmsRespondWithIdsGet	(void);
XMLSEC_EXPORT int 		xmlSecXkmsRespondWithIdsInit	(void);
XMLSEC_EXPORT void 		xmlSecXkmsRespondWithIdsShutdown(void);
XMLSEC_EXPORT int 		xmlSecXkmsRespondWithIdsRegisterDefault(void);
XMLSEC_EXPORT int		xmlSecXkmsRespondWithIdsRegister(xmlSecXkmsRespondWithId id);

XMLSEC_EXPORT int  		xmlSecXkmsRespondWithNodeRead	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);
XMLSEC_EXPORT int  		xmlSecXkmsRespondWithNodeWrite	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);
XMLSEC_EXPORT void		xmlSecXkmsRespondWithDebugDump	(xmlSecXkmsRespondWithId id,
								 FILE* output);
XMLSEC_EXPORT void		xmlSecXkmsRespondWithDebugXmlDump(xmlSecXkmsRespondWithId id,
								 FILE* output);
XMLSEC_EXPORT int  		xmlSecXkmsRespondWithDefaultNodeRead(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);
XMLSEC_EXPORT int  		xmlSecXkmsRespondWithDefaultNodeWrite(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);

typedef int  		(*xmlSecXkmsRespondWithNodeReadMethod)	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);
typedef int  		(*xmlSecXkmsRespondWithNodeWriteMethod)	(xmlSecXkmsRespondWithId id,
								 xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);
struct _xmlSecXkmsRespondWithKlass {
    const xmlChar*				name;
    const xmlChar*				nodeName;
    const xmlChar*				nodeNs;
    
    xmlSecXkmsRespondWithNodeReadMethod		readNode;
    xmlSecXkmsRespondWithNodeWriteMethod	writeNode;
};

#define xmlSecXkmsRespondWithKlassGetName(id) \
	((((id) != NULL) && ((id)->name != NULL)) ? (id)->name : NULL)

/************************************************************************
 *
 * XKMS RespondWith Klass List
 *
 ************************************************************************/ 
/**
 * xmlSecXkmsRespondWithIdListId:
 *
 * XKMS RespondWith  klasses list klass.
 */
#define xmlSecXkmsRespondWithIdListId	xmlSecXkmsRespondWithIdListGetKlass()
XMLSEC_EXPORT xmlSecPtrListId	xmlSecXkmsRespondWithIdListGetKlass(void);
XMLSEC_EXPORT int		xmlSecXkmsRespondWithIdListFind	(xmlSecPtrListPtr list,
								 xmlSecXkmsRespondWithId id);
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithIdListFindByName
								(xmlSecPtrListPtr list,
								 const xmlChar* name);
XMLSEC_EXPORT int		xmlSecXkmsRespondWithIdListWrite(xmlSecPtrListPtr list,
								 xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);

/******************************************************************** 
 *
 * XML Sec Library RespondWith Ids
 *
 *******************************************************************/
/**
 * xmlSecXkmsRespondWithIdUnknown:
 *
 * The "unknown" RespondWith id (NULL).
 */
#define xmlSecXkmsRespondWithIdUnknown			NULL

/**
 * xmlSecXkmsRespondWithKeyNameId:
 *
 * The respond with KeyName klass.
 */ 
#define xmlSecXkmsRespondWithKeyNameId \
	xmlSecXkmsRespondWithKeyNameGetKlass()
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithKeyNameGetKlass(void);

/**
 * xmlSecXkmsRespondWithKeyValueId:
 *
 * The respond with KeyValue klass.
 */ 
#define xmlSecXkmsRespondWithKeyValueId \
	xmlSecXkmsRespondWithKeyValueGetKlass()
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithKeyValueGetKlass(void);

/**
 * xmlSecXkmsRespondWithPrivateKeyId:
 *
 * The respond with PrivateKey klass.
 */ 
#define xmlSecXkmsRespondWithPrivateKeyId \
	xmlSecXkmsRespondWithPrivateKeyGetKlass()
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithPrivateKeyGetKlass(void);

/**
 * xmlSecXkmsRespondWithRetrievalMethodId:
 *
 * The respond with RetrievalMethod klass.
 */ 
#define xmlSecXkmsRespondWithRetrievalMethodId \
	xmlSecXkmsRespondWithRetrievalMethodGetKlass()
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithRetrievalMethodGetKlass(void);

/**
 * xmlSecXkmsRespondWithX509CertId:
 *
 * The respond with X509Cert klass.
 */ 
#define xmlSecXkmsRespondWithX509CertId \
	xmlSecXkmsRespondWithX509CertGetKlass()
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithX509CertGetKlass(void);

/**
 * xmlSecXkmsRespondWithX509ChainId:
 *
 * The respond with X509Chain klass.
 */ 
#define xmlSecXkmsRespondWithX509ChainId \
	xmlSecXkmsRespondWithX509ChainGetKlass()
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithX509ChainGetKlass(void);

/**
 * xmlSecXkmsRespondWithX509CRLId:
 *
 * The respond with X509CRL klass.
 */ 
#define xmlSecXkmsRespondWithX509CRLId \
	xmlSecXkmsRespondWithX509CRLGetKlass()
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithX509CRLGetKlass(void);


/**
 * xmlSecXkmsRespondWithPGPId:
 *
 * The respond with PGP klass.
 */ 
#define xmlSecXkmsRespondWithPGPId \
	xmlSecXkmsRespondWithPGPGetKlass()
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithPGPGetKlass(void);

/**
 * xmlSecXkmsRespondWithSPKIId:
 *
 * The respond with SPKI klass.
 */ 
#define xmlSecXkmsRespondWithSPKIId \
	xmlSecXkmsRespondWithSPKIGetKlass()
XMLSEC_EXPORT xmlSecXkmsRespondWithId	xmlSecXkmsRespondWithSPKIGetKlass(void);


/************************************************************************
 *
 * XKMS ServerRequest Klass
 *
 ************************************************************************/ 
XMLSEC_EXPORT xmlSecPtrListPtr	xmlSecXkmsServerRequestIdsGet	(void);
XMLSEC_EXPORT int 		xmlSecXkmsServerRequestIdsInit	(void);
XMLSEC_EXPORT void 		xmlSecXkmsServerRequestIdsShutdown
								(void);
XMLSEC_EXPORT int 		xmlSecXkmsServerRequestIdsRegisterDefault
								(void);
XMLSEC_EXPORT int		xmlSecXkmsServerRequestIdsRegister	
								(xmlSecXkmsServerRequestId id);

XMLSEC_EXPORT int  		xmlSecXkmsServerRequestNodeRead	(xmlSecXkmsServerRequestId id,
								 xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);
XMLSEC_EXPORT int  		xmlSecXkmsServerRequestExecute	(xmlSecXkmsServerRequestId id,
								 xmlSecXkmsServerCtxPtr ctx);
XMLSEC_EXPORT int  		xmlSecXkmsServerRequestNodeWrite(xmlSecXkmsServerRequestId id,
								 xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);
XMLSEC_EXPORT void		xmlSecXkmsServerRequestDebugDump(xmlSecXkmsServerRequestId id,
								 FILE* output);
XMLSEC_EXPORT void		xmlSecXkmsServerRequestDebugXmlDump
								(xmlSecXkmsServerRequestId id,
								 FILE* output);

typedef int  			(*xmlSecXkmsServerRequestNodeReadMethod)
								(xmlSecXkmsServerRequestId id,
								 xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);
typedef int  			(*xmlSecXkmsServerRequestExecuteMethod)
								(xmlSecXkmsServerRequestId id,
								 xmlSecXkmsServerCtxPtr ctx);
typedef int  			(*xmlSecXkmsServerRequestNodeWriteMethod)
								(xmlSecXkmsServerRequestId id,
								 xmlSecXkmsServerCtxPtr ctx,
								 xmlNodePtr node);
/** 
 * XMLSEC_XKMS_SERVER_REQUEST_KLASS_ALLOWED_IN_COUMPOUND:
 *
 * This request/response can be a part of CompundRequest/CompoundResponse.
 */
#define XMLSEC_XKMS_SERVER_REQUEST_KLASS_ALLOWED_IN_COUMPOUND	0x00000001

struct _xmlSecXkmsServerRequestKlass {
    const xmlChar*				name;
    const xmlChar*				requestNodeName;
    const xmlChar*				requestNodeNs;
    const xmlChar*				resultNodeName;
    const xmlChar*				resultNodeNs;
    xmlSecBitMask				flags;
    
    xmlSecXkmsServerRequestNodeReadMethod	readNode;
    xmlSecXkmsServerRequestNodeWriteMethod	writeNode;
    xmlSecXkmsServerRequestExecuteMethod	execute;
    
    void*					reserved1;
    void*					reserved2;
};

#define xmlSecXkmsServerRequestKlassGetName(id) \
	((((id) != NULL) && ((id)->name != NULL)) ? (id)->name : NULL)

/************************************************************************
 *
 * XKMS ServerRequest Klass List
 *
 ************************************************************************/ 
/**
 * xmlSecXkmsServerRequestIdListId:
 *
 * XKMS ServerRequest  klasses list klass.
 */
#define xmlSecXkmsServerRequestIdListId	xmlSecXkmsServerRequestIdListGetKlass()
XMLSEC_EXPORT xmlSecPtrListId	xmlSecXkmsServerRequestIdListGetKlass
								(void);
XMLSEC_EXPORT int		xmlSecXkmsServerRequestIdListFind
								(xmlSecPtrListPtr list,
								 xmlSecXkmsServerRequestId id);
XMLSEC_EXPORT xmlSecXkmsServerRequestId	xmlSecXkmsServerRequestIdListFindByName
								(xmlSecPtrListPtr list,
								 const xmlChar* name);
XMLSEC_EXPORT xmlSecXkmsServerRequestId	xmlSecXkmsServerRequestIdListFindByNode
								(xmlSecPtrListPtr list,
								 xmlNodePtr node);

/**
 * xmlSecXkmsServerRequestIdUnknown:
 *
 * The "unknown" ServerRequest id (NULL).
 */
#define xmlSecXkmsServerRequestIdUnknown			NULL

/**
 * xmlSecXkmsServerRequestResultId:
 *
 * The Result response klass.
 */ 
#define xmlSecXkmsServerRequestResultId \
	xmlSecXkmsServerRequestResultGetKlass()
XMLSEC_EXPORT xmlSecXkmsServerRequestId	xmlSecXkmsServerRequestResultGetKlass(void);

/**
 * xmlSecXkmsServerRequestStatusId:
 *
 * The StatusRequest klass.
 */ 
#define xmlSecXkmsServerRequestStatusId \
	xmlSecXkmsServerRequestStatusGetKlass()
XMLSEC_EXPORT xmlSecXkmsServerRequestId	xmlSecXkmsServerRequestStatusGetKlass(void);

/**
 * xmlSecXkmsServerRequestCompoundId:
 *
 * The CompoundRequest klass.
 */ 
#define xmlSecXkmsServerRequestCompoundId \
	xmlSecXkmsServerRequestCompoundGetKlass()
XMLSEC_EXPORT xmlSecXkmsServerRequestId	xmlSecXkmsServerRequestCompoundGetKlass(void);

/**
 * xmlSecXkmsServerRequestLocateId:
 *
 * The LocateRequest klass.
 */ 
#define xmlSecXkmsServerRequestLocateId \
	xmlSecXkmsServerRequestLocateGetKlass()
XMLSEC_EXPORT xmlSecXkmsServerRequestId	xmlSecXkmsServerRequestLocateGetKlass(void);

/**
 * xmlSecXkmsServerRequestValidateId:
 *
 * The ValidateRequest klass.
 */ 
#define xmlSecXkmsServerRequestValidateId \
	xmlSecXkmsServerRequestValidateGetKlass()
XMLSEC_EXPORT xmlSecXkmsServerRequestId	xmlSecXkmsServerRequestValidateGetKlass(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_NO_XKMS */

#endif /* __XMLSEC_XKMS_H__ */

