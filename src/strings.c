/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * All the string constants.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>

/*************************************************************************
 *
 * Global Namespaces
 *
 ************************************************************************/
const xmlChar xmlSecNs[] 			= "http://www.aleksey.com/xmlsec/2002";
const xmlChar xmlSecDSigNs[] 			= "http://www.w3.org/2000/09/xmldsig#";
const xmlChar xmlSecEncNs[] 			= "http://www.w3.org/2001/04/xmlenc#";
const xmlChar xmlSecXkmsNs[] 			= "http://www.w3.org/2002/03/xkms#";
const xmlChar xmlSecXPathNs[] 			= "http://www.w3.org/TR/1999/REC-xpath-19991116";
const xmlChar xmlSecXPath2Ns[] 			= "http://www.w3.org/2002/06/xmldsig-filter2";
const xmlChar xmlSecXPointerNs[]		= "http://www.w3.org/2001/04/xmldsig-more/xptr";

/*************************************************************************
 *
 * DSig Nodes
 *
 ************************************************************************/
const xmlChar xmlSecNodeSignature[]		= "Signature";
const xmlChar xmlSecNodeSignedInfo[]		= "SignedInfo";
const xmlChar xmlSecNodeCanonicalizationMethod[]= "CanonicalizationMethod";
const xmlChar xmlSecNodeSignatureMethod[]	= "SignatureMethod";
const xmlChar xmlSecNodeSignatureValue[]	= "SignatureValue";
const xmlChar xmlSecNodeDigestMethod[]		= "DigestMethod";
const xmlChar xmlSecNodeDigestValue[]		= "DigestValue";
const xmlChar xmlSecNodeObject[]		= "Object";
const xmlChar xmlSecNodeManifest[]		= "Manifest";
const xmlChar xmlSecNodeSignatureProperties[]	= "SignatureProperties";

/*************************************************************************
 *
 * Encryption Nodes
 *
 ************************************************************************/
const xmlChar xmlSecNodeEncryptedData[]		= "EncryptedData";
const xmlChar xmlSecNodeEncryptionMethod[]	= "EncryptionMethod";
const xmlChar xmlSecNodeEncryptionProperties[]	= "EncryptionProperties";
const xmlChar xmlSecNodeEncryptionProperty[]	= "EncryptionProperty";
const xmlChar xmlSecNodeCipherData[]		= "CipherData";
const xmlChar xmlSecNodeCipherValue[]		= "CipherValue";
const xmlChar xmlSecNodeCipherReference[]	= "CipherReference";
const xmlChar xmlSecNodeReferenceList[]		= "ReferenceList";
const xmlChar xmlSecNodeDataReference[]         = "DataReference";
const xmlChar xmlSecNodeKeyReference[]          = "KeyReference";

const xmlChar xmlSecNodeCarriedKeyName[]	= "CarriedKeyName";

const xmlChar xmlSecTypeEncContent[]		= "http://www.w3.org/2001/04/xmlenc#Content";
const xmlChar xmlSecTypeEncElement[]		= "http://www.w3.org/2001/04/xmlenc#Element";

/*************************************************************************
 *
 * XKMS Nodes
 *
 ************************************************************************/
#ifndef XMLSEC_NO_XKMS
const xmlChar xmlSecNodeLocateRequest[]		= "LocateRequest";
const xmlChar xmlSecNodeLocateResult[]		= "LocateResult";
const xmlChar xmlSecNodeValidateRequest[]	= "ValidateRequest";
const xmlChar xmlSecNodeValidateResult[]	= "ValidateResult";
const xmlChar xmlSecNodeCompoundRequest[]	= "CompoundRequest";
const xmlChar xmlSecNodeCompoundResult[]	= "CompoundResult";

const xmlChar xmlSecNodeMessageExtension[]	= "MessageExtension";
const xmlChar xmlSecNodeOpaqueClientData[]	= "OpaqueClientData";
const xmlChar xmlSecNodeResponseMechanism[]	= "ResponseMechanism";
const xmlChar xmlSecNodeRespondWith[]		= "RespondWith";
const xmlChar xmlSecNodePendingNotification[]	= "PendingNotification";
const xmlChar xmlSecNodeQueryKeyBinding[]	= "QueryKeyBinding";
const xmlChar xmlSecNodeKeyUsage[]		= "KeyUsage";
const xmlChar xmlSecNodeUseKeyWith[]		= "UseKeyWith";
const xmlChar xmlSecNodeTimeInstant[]		= "TimeInstant";
const xmlChar xmlSecNodeRequestSignatureValue[]	= "RequestSignatureValue";
const xmlChar xmlSecNodeUnverifiedKeyBinding[]	= "UnverifiedKeyBinding";
const xmlChar xmlSecNodeValidityInterval[]	= "ValidityInterval";

const xmlChar xmlSecAttrService[]		= "Service";
const xmlChar xmlSecAttrNonce[]			= "Nonce";
const xmlChar xmlSecAttrOriginalRequestId[]	= "OriginalRequestId";
const xmlChar xmlSecAttrResponseLimit[]		= "ResponseLimit";
const xmlChar xmlSecAttrMechanism[]		= "Mechanism[";
const xmlChar xmlSecAttrIdentifier[]		= "Identifier";
const xmlChar xmlSecAttrApplication[]		= "Application";
const xmlChar xmlSecAttrResultMajor[]		= "ResultMajor";
const xmlChar xmlSecAttrResultMinor[]		= "ResultMinor";
const xmlChar xmlSecAttrRequestId[]		= "RequestId";
const xmlChar xmlSecAttrNotBefore[]		= "NotBefore";
const xmlChar xmlSecAttrNotOnOrAfter[]		= "NotOnOrAfter";
const xmlChar xmlSecAttrTime[]			= "Time";

const xmlChar xmlSecResponsePending[]		= "Pending";
const xmlChar xmlSecResponseRepresent[]		= "Represent";
const xmlChar xmlSecResponseRequestSignatureValue[] = "RequestSignatureValue";

const xmlChar xmlSecRespondWithKeyName[]	= "KeyName";
const xmlChar xmlSecRespondWithKeyValue[]	= "KeyValue";
const xmlChar xmlSecRespondWithX509Cert[]	= "X509Cert";
const xmlChar xmlSecRespondWithX509Chain[]	= "X509Chain";
const xmlChar xmlSecRespondWithX509CRL[]	= "X509CRL";
const xmlChar xmlSecRespondWithOCSP[]		= "OCSP";
const xmlChar xmlSecRespondWithRetrievalMethod[]= "RetrievalMethod";
const xmlChar xmlSecRespondWithPGP[]		= "PGP";
const xmlChar xmlSecRespondWithPGPWeb[]		= "PGPWeb";
const xmlChar xmlSecRespondWithSPKI[]		= "SPKI";
const xmlChar xmlSecRespondWithPrivateKey[]	= "PrivateKey";

const xmlChar xmlSecStatusResultSuccess[]	= "Success";
const xmlChar xmlSecStatusResultFailed[]	= "Failed";
const xmlChar xmlSecStatusResultPending[]	= "Pending";

const xmlChar xmlSecKeyUsageEncryption[]	= "Encryption";
const xmlChar xmlSecKeyUsageSignature[]		= "Signature";
const xmlChar xmlSecKeyUsageExchange[]		= "Exchange";

const xmlChar xmlSecResultMajorCodeSuccess[]	= "Success";
const xmlChar xmlSecResultMajorCodeVersionMismatch[]= "VersionMismatch";
const xmlChar xmlSecResultMajorCodeSender[]	= "Sender";
const xmlChar xmlSecResultMajorCodeReceiver[]	= "Receiver";
const xmlChar xmlSecResultMajorCodeRepresent[]	= "Represent";
const xmlChar xmlSecResultMajorCodePending[]	= "Pending";
const xmlChar xmlSecResultMinorCodeNoMatch[]	= "NoMatch";
const xmlChar xmlSecResultMinorCodeTooManyResponses[]	= "TooManyResponses";
const xmlChar xmlSecResultMinorCodeIncomplete[]	= "Incomplete";
const xmlChar xmlSecResultMinorCodeFailure[]	= "Failure";
const xmlChar xmlSecResultMinorCodeRefused[]	= "Refused";
const xmlChar xmlSecResultMinorCodeNoAuthentication[]	= "NoAuthentication";
const xmlChar xmlSecResultMinorCodeMessageNotSupported[]= "MessageNotSupported";
const xmlChar xmlSecResultMinorCodeUnknownResponseId[]	= "UnknownResponseId";
const xmlChar xmlSecResultMinorCodeNotSynchronous[]	= "NotSynchronous";
#endif /* XMLSEC_NO_XKMS */

/*************************************************************************
 *
 * KeyInfo Nodes
 *
 ************************************************************************/
const xmlChar xmlSecNodeKeyInfo[]		= "KeyInfo";
const xmlChar xmlSecNodeReference[]		= "Reference";
const xmlChar xmlSecNodeTransforms[]		= "Transforms";
const xmlChar xmlSecNodeTransform[]		= "Transform";

/*************************************************************************
 *
 * Attributes
 *
 ************************************************************************/
const xmlChar xmlSecAttrId[]			= "Id";
const xmlChar xmlSecAttrURI[]			= "URI";
const xmlChar xmlSecAttrType[]			= "Type";
const xmlChar xmlSecAttrMimeType[]		= "MimeType";
const xmlChar xmlSecAttrEncoding[]		= "Encoding";
const xmlChar xmlSecAttrAlgorithm[]		= "Algorithm";
const xmlChar xmlSecAttrFilter[]		= "Filter";
const xmlChar xmlSecAttrRecipient[]		= "Recipient";
const xmlChar xmlSecAttrTarget[]		= "Target";

/*************************************************************************
 *
 * AES strings
 *
 ************************************************************************/
const xmlChar xmlSecNameAESKeyValue[]		= "aes";
const xmlChar xmlSecNodeAESKeyValue[]		= "AESKeyValue";
const xmlChar xmlSecHrefAESKeyValue[]		= "http://www.aleksey.com/xmlsec/2002#AESKeyValue";

const xmlChar xmlSecNameAes128Cbc[]		= "aes128-cbc";
const xmlChar xmlSecHrefAes128Cbc[]		= "http://www.w3.org/2001/04/xmlenc#aes128-cbc";

const xmlChar xmlSecNameAes192Cbc[]		= "aes192-cbc";
const xmlChar xmlSecHrefAes192Cbc[]		= "http://www.w3.org/2001/04/xmlenc#aes192-cbc";

const xmlChar xmlSecNameAes256Cbc[]		= "aes256-cbc";
const xmlChar xmlSecHrefAes256Cbc[]		= "http://www.w3.org/2001/04/xmlenc#aes256-cbc";

const xmlChar xmlSecNameKWAes128[]		= "kw-aes128";
const xmlChar xmlSecHrefKWAes128[]		= "http://www.w3.org/2001/04/xmlenc#kw-aes128";

const xmlChar xmlSecNameKWAes192[]		= "kw-aes192";
const xmlChar xmlSecHrefKWAes192[]		= "http://www.w3.org/2001/04/xmlenc#kw-aes192";

const xmlChar xmlSecNameKWAes256[]		= "kw-aes256";
const xmlChar xmlSecHrefKWAes256[]		= "http://www.w3.org/2001/04/xmlenc#kw-aes256";

/*************************************************************************
 *
 * BASE64 strings
 *
 ************************************************************************/
const xmlChar xmlSecNameBase64[]		= "base64";
const xmlChar xmlSecHrefBase64[]		= "http://www.w3.org/2000/09/xmldsig#base64";

/*************************************************************************
 *
 * C14N strings
 *
 ************************************************************************/
const xmlChar xmlSecNameC14N[]			= "c14n";
const xmlChar xmlSecHrefC14N[]			= "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

const xmlChar xmlSecNameC14NWithComments[]	= "c14n-with-comments";
const xmlChar xmlSecHrefC14NWithComments[]	= "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";

const xmlChar xmlSecNameExcC14N[]		= "exc-c14n";
const xmlChar xmlSecHrefExcC14N[]		= "http://www.w3.org/2001/10/xml-exc-c14n#";

const xmlChar xmlSecNameExcC14NWithComments[]	= "exc-c14n-with-comments";
const xmlChar xmlSecHrefExcC14NWithComments[]	= "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

const xmlChar xmlSecNsExcC14N[]			= "http://www.w3.org/2001/10/xml-exc-c14n#";
const xmlChar xmlSecNsExcC14NWithComments[]	= "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

const xmlChar xmlSecNodeInclusiveNamespaces[]	= "InclusiveNamespaces";
const xmlChar xmlSecAttrPrefixList[]		= "PrefixList";
/*************************************************************************
 *
 * DES strings
 *
 ************************************************************************/
const xmlChar xmlSecNameDESKeyValue[]		= "des";
const xmlChar xmlSecNodeDESKeyValue[]		= "DESKeyValue";
const xmlChar xmlSecHrefDESKeyValue[]		= "http://www.aleksey.com/xmlsec/2002#DESKeyValue";

const xmlChar xmlSecNameDes3Cbc[]		= "tripledes-cbc";
const xmlChar xmlSecHrefDes3Cbc[]		= "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";

const xmlChar xmlSecNameKWDes3[]		= "kw-tripledes";
const xmlChar xmlSecHrefKWDes3[]		= "http://www.w3.org/2001/04/xmlenc#kw-tripledes";

/*************************************************************************
 *
 * DSA strings
 *
 ************************************************************************/
const xmlChar xmlSecNameDSAKeyValue[]		= "dsa";
const xmlChar xmlSecNodeDSAKeyValue[]		= "DSAKeyValue";
const xmlChar xmlSecHrefDSAKeyValue[]		= "http://www.w3.org/2000/09/xmldsig#DSAKeyValue";
const xmlChar xmlSecNodeDSAP[]			= "P";
const xmlChar xmlSecNodeDSAQ[]			= "Q";
const xmlChar xmlSecNodeDSAG[]			= "G";
const xmlChar xmlSecNodeDSAX[]			= "X";
const xmlChar xmlSecNodeDSAY[]			= "Y";
const xmlChar xmlSecNodeDSASeed[]		= "Seed";
const xmlChar xmlSecNodeDSAPgenCounter[]	= "PgenCounter";

const xmlChar xmlSecNameDsaSha1[]		= "dsa-sha1";
const xmlChar xmlSecHrefDsaSha1[]		= "http://www.w3.org/2000/09/xmldsig#dsa-sha1";

/*************************************************************************
 *
 * EncryptedKey
 *
 ************************************************************************/
const xmlChar xmlSecNameEncryptedKey[]		= "enc-key";
const xmlChar xmlSecNodeEncryptedKey[]		= "EncryptedKey";
const xmlChar xmlSecHrefEncryptedKey[]		= "http://www.w3.org/2001/04/xmlenc#EncryptedKey";

/*************************************************************************
 *
 * Enveloped transform strings
 *
 ************************************************************************/
const xmlChar xmlSecNameEnveloped[]		= "enveloped-signature";
const xmlChar xmlSecHrefEnveloped[]		= "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/*************************************************************************
 *
 * HMAC strings
 *
 ************************************************************************/
const xmlChar xmlSecNameHMACKeyValue[]		= "hmac";
const xmlChar xmlSecNodeHMACKeyValue[]		= "HMACKeyValue";
const xmlChar xmlSecHrefHMACKeyValue[]		= "http://www.aleksey.com/xmlsec/2002#HMACKeyValue";

const xmlChar xmlSecNodeHMACOutputLength[] 	= "HMACOutputLength";

const xmlChar xmlSecNameHmacSha1[]		= "hmac-sha1";
const xmlChar xmlSecHrefHmacSha1[]		= "http://www.w3.org/2000/09/xmldsig#hmac-sha1";

const xmlChar xmlSecNameHmacRipemd160[]		= "hmac-ripemd160";
const xmlChar xmlSecHrefHmacRipemd160[]		= "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160";

const xmlChar xmlSecNameHmacMd5[]		= "hmac-md5";
const xmlChar xmlSecHrefHmacMd5[]		= "http://www.w3.org/2001/04/xmldsig-more#hmac-md5";

/*************************************************************************
 *
 * KeyName strings
 *
 ************************************************************************/
const xmlChar xmlSecNameKeyName[]		= "key-name";
const xmlChar xmlSecNodeKeyName[]		= "KeyName";

/*************************************************************************
 *
 * KeyValue strings
 *
 ************************************************************************/
const xmlChar xmlSecNameKeyValue[]		= "key-value";
const xmlChar xmlSecNodeKeyValue[]		= "KeyValue";

/*************************************************************************
 *
 * Memory Buffer strings
 *
 ************************************************************************/
const xmlChar xmlSecNameMemBuf[]		= "membuf-transform";

/*************************************************************************
 *
 * RetrievalMethod
 *
 ************************************************************************/
const xmlChar xmlSecNameRetrievalMethod[] 	= "retrieval-method";
const xmlChar xmlSecNodeRetrievalMethod[] 	= "RetrievalMethod";

/*************************************************************************
 *
 * RIPEMD160 strings
 *
 ************************************************************************/
const xmlChar xmlSecNameRipemd160[]		= "ripemd160";
const xmlChar xmlSecHrefRipemd160[]		= "http://www.w3.org/2001/04/xmlenc#ripemd160";

/*************************************************************************
 *
 * RSA strings
 *
 ************************************************************************/
const xmlChar xmlSecNameRSAKeyValue[]		= "rsa";
const xmlChar xmlSecNodeRSAKeyValue[]		= "RSAKeyValue";
const xmlChar xmlSecHrefRSAKeyValue[]		= "http://www.w3.org/2000/09/xmldsig#RSAKeyValue";
const xmlChar xmlSecNodeRSAModulus[]		= "Modulus";
const xmlChar xmlSecNodeRSAExponent[]		= "Exponent";
const xmlChar xmlSecNodeRSAPrivateExponent[] 	= "PrivateExponent";

const xmlChar xmlSecNameRsaSha1[]		= "rsa-sha1";
const xmlChar xmlSecHrefRsaSha1[]		= "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

const xmlChar xmlSecNameRsaPkcs1[]		= "rsa-1_5";
const xmlChar xmlSecHrefRsaPkcs1[]		= "http://www.w3.org/2001/04/xmlenc#rsa-1_5";

const xmlChar xmlSecNameRsaOaep[]		= "rsa-oaep-mgf1p";
const xmlChar xmlSecHrefRsaOaep[]		= "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
const xmlChar xmlSecNodeRsaOAEPparams[]		= "OAEPparams";

/*************************************************************************
 *
 * SHA1 strings
 *
 ************************************************************************/
const xmlChar xmlSecNameSha1[]			= "sha1";
const xmlChar xmlSecHrefSha1[]			= "http://www.w3.org/2000/09/xmldsig#sha1";

/*************************************************************************
 *
 * X509 strings
 *
 ************************************************************************/
const xmlChar xmlSecNameX509Data[]		= "x509";
const xmlChar xmlSecNodeX509Data[]		= "X509Data";
const xmlChar xmlSecHrefX509Data[]		= "http://www.w3.org/2000/09/xmldsig#X509Data";

const xmlChar xmlSecNodeX509Certificate[]	= "X509Certificate";
const xmlChar xmlSecNodeX509CRL[]		= "X509CRL";
const xmlChar xmlSecNodeX509SubjectName[]	= "X509SubjectName";
const xmlChar xmlSecNodeX509IssuerSerial[]	= "X509IssuerSerial";
const xmlChar xmlSecNodeX509IssuerName[]	= "X509IssuerName";
const xmlChar xmlSecNodeX509SerialNumber[]	= "X509SerialNumber";
const xmlChar xmlSecNodeX509SKI[]		= "X509SKI";

const xmlChar xmlSecNameRawX509Cert[]		= "raw-x509-cert";
const xmlChar xmlSecHrefRawX509Cert[]		= "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";

const xmlChar xmlSecNameX509Store[]		= "x509-store";

/*************************************************************************
 *
 * PGP strings
 *
 ************************************************************************/
const xmlChar xmlSecNamePGPData[]		= "pgp";
const xmlChar xmlSecNodePGPData[]		= "PGPData";
const xmlChar xmlSecHrefPGPData[]		= "http://www.w3.org/2000/09/xmldsig#PGPData";

/*************************************************************************
 *
 * SPKI strings
 *
 ************************************************************************/
const xmlChar xmlSecNameSPKIData[]		= "spki";
const xmlChar xmlSecNodeSPKIData[]		= "SPKIData";
const xmlChar xmlSecHrefSPKIData[]		= "http://www.w3.org/2000/09/xmldsig#SPKIData";

/*************************************************************************
 *
 * XPath/XPointer strings
 *
 ************************************************************************/
const xmlChar xmlSecNameXPath[]			= "xpath";
const xmlChar xmlSecNodeXPath[]			= "XPath";

const xmlChar xmlSecNameXPath2[]		= "xpath2";
const xmlChar xmlSecNodeXPath2[]		= "XPath";
const xmlChar xmlSecXPath2FilterIntersect[]	= "intersect";
const xmlChar xmlSecXPath2FilterSubtract[]	= "subtract";
const xmlChar xmlSecXPath2FilterUnion[]		= "union";

const xmlChar xmlSecNameXPointer[]		= "xpointer";
const xmlChar xmlSecNodeXPointer[]		= "XPointer";

/*************************************************************************
 *
 * Xslt strings
 *
 ************************************************************************/
const xmlChar xmlSecNameXslt[]			= "xslt";
const xmlChar xmlSecHrefXslt[]			= "http://www.w3.org/TR/1999/REC-xslt-19991116";

/*************************************************************************
 *
 * Utility strings
 *
 ************************************************************************/
const xmlChar xmlSecStringEmpty[]		= "";
const xmlChar xmlSecStringCR[]			= "\n";






