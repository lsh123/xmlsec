/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * All the string constans.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_STRINGS_H__
#define __XMLSEC_STRINGS_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>

/*************************************************************************
 *
 * Global Namespaces
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNs[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecDSigNs[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecEncNs[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecXkmsNs[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecXPathNs[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecXPath2Ns[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecXPointerNs[];


/*************************************************************************
 *
 * DSig Nodes
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeSignature[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeSignedInfo[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeSignatureValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeCanonicalizationMethod[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeSignatureMethod[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeDigestMethod[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeDigestValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeObject[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeManifest[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeSignatureProperties[];

/*************************************************************************
 *
 * Encryption Nodes
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeEncryptedData[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeEncryptionMethod[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeEncryptionProperties[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeEncryptionProperty[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeCipherData[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeCipherValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeCipherReference[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeReferenceList[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeCarriedKeyName[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecTypeEncContent[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecTypeEncElement[];

/*************************************************************************
 *
 * XKMS nodes, attributes  and value strings
 *
 ************************************************************************/
#ifndef XMLSEC_NO_XKMS
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeLocateRequest[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeLocateResult[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeValidateRequest[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeValidateResult[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeCompoundRequest[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeCompoundResult[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeMessageExtension[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeOpaqueClientData[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeResponseMechanism[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeRespondWith[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodePendingNotification[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeQueryKeyBinding[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeKeyUsage[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeUseKeyWith[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeTimeInstant[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeRequestSignatureValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeUnverifiedKeyBinding[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeValidityInterval[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrService[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrNonce[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrOriginalRequestId[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrResponseLimit[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrMechanism[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrIdentifier[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrApplication[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrResultMajor[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrResultMinor[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrRequestId[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrNotBefore[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrNotOnOrAfter[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrTime[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecResponsePending[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecResponseRepresent[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecResponseRequestSignatureValue[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecRespondWithKeyName[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecRespondWithKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecRespondWithX509Cert[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecRespondWithX509Chain[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecRespondWithX509CRL[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecRespondWithOCSP[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecRespondWithRetrievalMethod[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecRespondWithPGP[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecRespondWithPGPWeb[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecRespondWithSPKI[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecRespondWithPrivateKey[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecStatusResultSuccess[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecStatusResultFailed[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecStatusResultPending[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecKeyUsageEncryption[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecKeyUsageSignature[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecKeyUsageExchange[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecResultMajorCodeSuccess[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecResultMajorCodeVersionMismatch[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecResultMajorCodeSender[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecResultMajorCodeReceiver[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecResultMajorCodeRepresent[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecResultMajorCodePending[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecResultMinorCodeNoMatch[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecResultMinorCodeTooManyResponses[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecResultMinorCodeIncomplete[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecResultMinorCodeFailure[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecResultMinorCodeRefused[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecResultMinorCodeNoAuthentication[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecResultMinorCodeMessageNotSupported[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecResultMinorCodeUnknownResponseId[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecResultMinorCodeNotSynchronous[];
#endif /* XMLSEC_NO_XKMS */

/*************************************************************************
 *
 * KeyInfo and Transform Nodes
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeKeyInfo[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeReference[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeTransforms[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeTransform[];

/*************************************************************************
 *
 * Attributes
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrId[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrURI[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrType[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrMimeType[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrEncoding[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrAlgorithm[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrTarget[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrFilter[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrRecipient[];

/*************************************************************************
 *
 * AES strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameAESKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeAESKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefAESKeyValue[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameAes128Cbc[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefAes128Cbc[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameAes192Cbc[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefAes192Cbc[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameAes256Cbc[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefAes256Cbc[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameKWAes128[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefKWAes128[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameKWAes192[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefKWAes192[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameKWAes256[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefKWAes256[];

/*************************************************************************
 *
 * BASE64 strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameBase64[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefBase64[];

/*************************************************************************
 *
 * C14N strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameC14N[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefC14N[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameC14NWithComments[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefC14NWithComments[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameExcC14N[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefExcC14N[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameExcC14NWithComments[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefExcC14NWithComments[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNsExcC14N[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNsExcC14NWithComments[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeInclusiveNamespaces[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrPrefixList[];

/*************************************************************************
 *
 * DES strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameDESKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeDESKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefDESKeyValue[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameDes3Cbc[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefDes3Cbc[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameKWDes3[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefKWDes3[];

/*************************************************************************
 *
 * DSA strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameDSAKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeDSAKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefDSAKeyValue[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeDSAP[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeDSAQ[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeDSAG[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeDSAX[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeDSAY[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeDSASeed[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeDSAPgenCounter[];


XMLSEC_EXPORT_VAR const xmlChar xmlSecNameDsaSha1[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefDsaSha1[];

/*************************************************************************
 *
 * EncryptedKey
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameEncryptedKey[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeEncryptedKey[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefEncryptedKey[];

/*************************************************************************
 *
 * Enveloped transform strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameEnveloped[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefEnveloped[];

/*************************************************************************
 *
 * HMAC strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameHMACKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeHMACKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefHMACKeyValue[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeHMACOutputLength[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameHmacSha1[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefHmacSha1[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameHmacRipemd160[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefHmacRipemd160[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameHmacMd5[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefHmacMd5[];

/*************************************************************************
 *
 * KeyName strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameKeyName[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeKeyName[];

/*************************************************************************
 *
 * KeyValue strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeKeyValue[];

/*************************************************************************
 *
 * Memory Buffer strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameMemBuf[];

/*************************************************************************
 *
 * RetrievalMethod
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameRetrievalMethod[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeRetrievalMethod[];

/*************************************************************************
 *
 * RIPEMD160 strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameRipemd160[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRipemd160[];

/*************************************************************************
 *
 * RSA strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameRSAKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeRSAKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRSAKeyValue[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeRSAModulus[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeRSAExponent[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeRSAPrivateExponent[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameRsaSha1[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRsaSha1[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameRsaPkcs1[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRsaPkcs1[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameRsaOaep[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRsaOaep[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeRsaOAEPparams[];

/*************************************************************************
 *
 * SHA1 strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameSha1[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefSha1[];

/*************************************************************************
 *
 * X509 strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameX509Data[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeX509Data[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefX509Data[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeX509Certificate[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeX509CRL[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeX509SubjectName[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeX509IssuerSerial[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeX509IssuerName[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeX509SerialNumber[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeX509SKI[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameRawX509Cert[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRawX509Cert[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameX509Store[];

/*************************************************************************
 *
 * PGP strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNamePGPData[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodePGPData[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefPGPData[];

/*************************************************************************
 *
 * SPKI strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameSPKIData[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeSPKIData[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefSPKIData[];

/*************************************************************************
 *
 * XPath/XPointer strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameXPath[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeXPath[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNameXPath2[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeXPath2[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecXPath2FilterIntersect[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecXPath2FilterSubtract[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecXPath2FilterUnion[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameXPointer[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeXPointer[];

/*************************************************************************
 *
 * Xslt strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameXslt[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefXslt[];

/*************************************************************************
 *
 * Utility strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecStringEmpty[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecStringCR[];

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_STRINGS_H__ */


