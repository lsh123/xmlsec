/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_STRINGS_H__
#define __XMLSEC_STRINGS_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <libxml/tree.h>
#include <xmlsec/xmlsec.h>

/**
 * xmlSecNs:
 * 
 * The  XML Security library namespace 
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecNs[];

/**
 * xmlSecNsDSig:
 *
 * The XML DSig namespace 
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecNsDSig[];

/**
 * xmlSecNsEnc:
 *
 * The XML Encription namespace 
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecNsEnc[];


/**
 * xmlSecNsXPath2:
 * 
 * The XPath2 transform namespace 
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecNsXPath2[];

/**
 * xmlSecNsXPointer:
 *
 * XPointer transform namespace 
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecNsXPointer[];

/**
 * xmlSecNsExcC14NNs:
 *
 * XPointer transform namespace 
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecNsExcC14N[];

/* KeyInfo children names */
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameKeyName[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameRetreivalMethod[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameX509Data[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNamePgpData[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameSpkiData[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameMgmtData[];

/* KeyValue children names */
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameAesKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameDesKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameDsaKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameHmacKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNameRsaKeyValue[];

/* known RetrievalMethod hrefs */
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRetrievalMethodTypeDSAKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRetrievalMethodTypeRSAKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRetrievalMethodTypeX509Data[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRetrievalMethodTypePGPData[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRetrievalMethodTypeSPKIData[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRetrievalMethodTypeMgmtData[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRetrievalMethodTypeRawX509Cert[];

/* base64 hrefs */
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefBase64Decode[];

/* c14n algorithms hrefs */
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefC14NInclusiveTransform[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefC14NInclusiveWithCommentsTransform[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefC14NExclusiveTransform[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefC14NExclusiveWithCommentsTransform[];

/* xml transforms hrefs */
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefTransformEnveloped[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefXPathTransform[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefXPath2Transform[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefTransformXslt[];

/* digests algorithms hrefs */
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefDigestRipemd160[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefDigestSha1[];

/* signature algorithms hrefs */
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefSignDsaSha1[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefMacHmacSha1[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefMacHmacMd5[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefMacHmacRipeMd160[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefSignRsaSha1[];

/* encryption algorithm hrefs */
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefEncHrefAes128Cbc[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefEncHrefAes192Cbc[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefEncHrefAes256Cbc[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefEncHrefDes3Cbc[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefEncHrefRsaPkcs1[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefEncHrefRsaOaep[];

/* key wrap algorithm hrefs */
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefKWHrefAes128Cbc[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefKWHrefAes192Cbc[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefKWAes256Cbc[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefKWDes3Cbc[];

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_STRINGS_H__ */


