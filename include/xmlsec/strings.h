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

/*************************************************************************
 *
 * Global Namespaces
 *
 ************************************************************************/
/**
 * xmlSecNs:
 * 
 * The  XML Security library namespace 
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecNs[];

/**
 * xmlSecDSigNs:
 *
 * The XML DSig namespace 
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecDSigNs[];

/**
 * xmlSecEncNs:
 *
 * The XML Encription namespace 
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecEncNs[];

/*************************************************************************
 *
 * DSIG Nodes and attributes
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeDigestMethod[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrType[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrAlgorithm[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecAttrURI[];

/*************************************************************************
 *
 * AES strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const char xmlSecNameAESKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeAESKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefAESKeyValue[];

XMLSEC_EXPORT_VAR const char xmlSecNameAes128Cbc[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefAes128Cbc[];

XMLSEC_EXPORT_VAR const char xmlSecNameAes192Cbc[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefAes192Cbc[];

XMLSEC_EXPORT_VAR const char xmlSecNameAes256Cbc[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefAes256Cbc[];

XMLSEC_EXPORT_VAR const char xmlSecNameKWAes128[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefKWAes128[];

XMLSEC_EXPORT_VAR const char xmlSecNameKWAes192[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefKWAes192[];

XMLSEC_EXPORT_VAR const char xmlSecNameKWAes256[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefKWAes256[];

/*************************************************************************
 *
 * BASE64 strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const char xmlSecNameBase64[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefBase64[];

/*************************************************************************
 *
 * DES strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const char xmlSecNameDESKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeDESKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefDESKeyValue[];

XMLSEC_EXPORT_VAR const char xmlSecNameDes3Cbc[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefDes3Cbc[];

XMLSEC_EXPORT_VAR const char xmlSecNameKWDes3[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefKWDes3[];

/*************************************************************************
 *
 * DSA strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const char xmlSecNameDSAKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeDSAKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefDSAKeyValue[];

XMLSEC_EXPORT_VAR const char xmlSecNameDsaSha1[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefDsaSha1[];

/*************************************************************************
 *
 * HMAC strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const char xmlSecNameHMACKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeHMACKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefHMACKeyValue[];

XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeHMACOutputLength[];

XMLSEC_EXPORT_VAR const char xmlSecNameHmacSha1[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefHmacSha1[];

XMLSEC_EXPORT_VAR const char xmlSecNameHmacRipemd160[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefHmacRipemd160[];

XMLSEC_EXPORT_VAR const char xmlSecNameHmacMd5[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefHmacMd5[];

/*************************************************************************
 *
 * Memory Buffer strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const char xmlSecNameMemBuf[];

/*************************************************************************
 *
 * RIPEMD160 strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const char xmlSecNameRipemd160[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRipemd160[];

/*************************************************************************
 *
 * RSA strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const char xmlSecNameRSAKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeRSAKeyValue[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRSAKeyValue[];

XMLSEC_EXPORT_VAR const char xmlSecNameRsaSha1[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRsaSha1[];

XMLSEC_EXPORT_VAR const char xmlSecNameRsaPkcs1[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRsaPkcs1[];

XMLSEC_EXPORT_VAR const char xmlSecNameRsaOaep[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRsaOaep[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeRsaOAEPparams[];

/*************************************************************************
 *
 * SHA1 strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const char xmlSecNameSha1[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefSha1[];

/*************************************************************************
 *
 * X509 strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const char xmlSecNameX509Data[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeX509Data[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefX509Data[];

XMLSEC_EXPORT_VAR const char xmlSecNameRawX509Cert[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefRawX509Cert[];

/*************************************************************************
 *
 * Xslt strings
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const char xmlSecNameXslt[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefXslt[];



/*************************************************************************
 *
 * RetrievalMethod
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const char xmlSecNameRetrievalMethod[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeRetrievalMethod[];

/*************************************************************************
 *
 * EncryptedKey
 *
 ************************************************************************/
XMLSEC_EXPORT_VAR const char xmlSecNameEncryptedKey[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecNodeEncryptedKey[];
XMLSEC_EXPORT_VAR const xmlChar xmlSecHrefEncryptedKey[];








/**
 * xmlSecXPathNs:
 * 
 * The XPath transform namespace 
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecXPathNs[];

/**
 * xmlSecXPath2Ns:
 * 
 * The XPath2 transform namespace 
 */
XMLSEC_EXPORT_VAR const xmlChar xmlSecXPath2Ns[];

/* XPointer transform namespace */
XMLSEC_EXPORT_VAR const xmlChar xmlSecXPointerNs[];

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_STRINGS_H__ */


