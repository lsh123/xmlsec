/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>

/*************************************************************************
 *
 * Global Namespaces
 *
 ************************************************************************/
const xmlChar xmlSecNs[] 		= "http://www.aleksey.com/xmlsec/2002";
const xmlChar xmlSecDSigNs[] 		= "http://www.w3.org/2000/09/xmldsig#";
const xmlChar xmlSecEncNs[] 		= "http://www.w3.org/2001/04/xmlenc#";

/*************************************************************************
 *
 * DSIG Nodes and attributes
 *
 ************************************************************************/
const xmlChar xmlSecNodeDigestMethod[]	= "DigestMethod";

const xmlChar xmlSecAttrType[]		= "Type";
const xmlChar xmlSecAttrAlgorithm[]	= "Algorithm";
const xmlChar xmlSecAttrURI[]		= "URI";

/*************************************************************************
 *
 * AES strings
 *
 ************************************************************************/
const char xmlSecNameAESKeyValue[]	= "aes";
const xmlChar xmlSecNodeAESKeyValue[]	= "AESKeyValue";
const xmlChar xmlSecHrefAESKeyValue[]	= "http://www.aleksey.com/xmlsec/2002#AESKeyValue";

const char xmlSecNameAes128Cbc[]	= "aes128-cbc";
const xmlChar xmlSecHrefAes128Cbc[]	= "http://www.w3.org/2001/04/xmlenc#aes128-cbc";

const char xmlSecNameAes192Cbc[]	= "aes192-cbc";
const xmlChar xmlSecHrefAes192Cbc[]	= "http://www.w3.org/2001/04/xmlenc#aes192-cbc";

const char xmlSecNameAes256Cbc[]	= "aes256-cbc";
const xmlChar xmlSecHrefAes256Cbc[]	= "http://www.w3.org/2001/04/xmlenc#aes256-cbc";

const char xmlSecNameKWAes128[]		= "kw-aes128";
const xmlChar xmlSecHrefKWAes128[]	= "http://www.w3.org/2001/04/xmlenc#kw-aes128";

const char xmlSecNameKWAes192[]		= "kw-aes192";
const xmlChar xmlSecHrefKWAes192[]	= "http://www.w3.org/2001/04/xmlenc#kw-aes192";

const char xmlSecNameKWAes256[]		= "kw-aes256";
const xmlChar xmlSecHrefKWAes256[]	= "http://www.w3.org/2001/04/xmlenc#kw-aes256";

/*************************************************************************
 *
 * BASE64 strings
 *
 ************************************************************************/
const char xmlSecNameBase64[]		= "base64";
const xmlChar xmlSecHrefBase64[]	= "http://www.w3.org/2000/09/xmldsig#base64";

/*************************************************************************
 *
 * DES strings
 *
 ************************************************************************/
const char xmlSecNameDESKeyValue[]	= "des";
const xmlChar xmlSecNodeDESKeyValue[]	= "DESKeyValue";
const xmlChar xmlSecHrefDESKeyValue[]	= "http://www.aleksey.com/xmlsec/2002#DESKeyValue";

const char xmlSecNameDes3Cbc[]		= "tripledes-cbc";
const xmlChar xmlSecHrefDes3Cbc[]	= "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";

const char xmlSecNameKWDes3[]		= "kw-tripledes";
const xmlChar xmlSecHrefKWDes3[]	= "http://www.w3.org/2001/04/xmlenc#kw-tripledes";

/*************************************************************************
 *
 * DSA strings
 *
 ************************************************************************/
const char xmlSecNameDSAKeyValue[]	= "dsa";
const xmlChar xmlSecNodeDSAKeyValue[]	= "DSAKeyValue";
const xmlChar xmlSecHrefDSAKeyValue[]	= "http://www.w3.org/2000/09/xmldsig#DSAKeyValue";

const char xmlSecNameDsaSha1[]		= "dsa-sha1";
const xmlChar xmlSecHrefDsaSha1[]	= "http://www.w3.org/2000/09/xmldsig#dsa-sha1";

/*************************************************************************
 *
 * HMAC strings
 *
 ************************************************************************/
const char xmlSecNameHMACKeyValue[]	= "hmac";
const xmlChar xmlSecNodeHMACKeyValue[]	= "HMACKeyValue";
const xmlChar xmlSecHrefHMACKeyValue[]	= "http://www.aleksey.com/xmlsec/2002#HMACKeyValue";

const xmlChar xmlSecNodeHMACOutputLength[] = "HMACOutputLength";

const char xmlSecNameHmacSha1[]		= "hmac-sha1";
const xmlChar xmlSecHrefHmacSha1[]	= "http://www.w3.org/2000/09/xmldsig#hmac-sha1";

const char xmlSecNameHmacRipemd160[]	= "hmac-ripemd160";
const xmlChar xmlSecHrefHmacRipemd160[]	= "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160";

const char xmlSecNameHmacMd5[]		= "hmac-md5";
const xmlChar xmlSecHrefHmacMd5[]	= "http://www.w3.org/2001/04/xmldsig-more#hmac-md5";

/*************************************************************************
 *
 * Memory Buffer strings
 *
 ************************************************************************/
const char xmlSecNameMemBuf[]		= "membuf";

/*************************************************************************
 *
 * RIPEMD160 strings
 *
 ************************************************************************/
const char xmlSecNameRipemd160[]	= "ripemd160";
const xmlChar xmlSecHrefRipemd160[]	= "http://www.w3.org/2001/04/xmlenc#ripemd160";

/*************************************************************************
 *
 * RSA strings
 *
 ************************************************************************/
const char xmlSecNameRSAKeyValue[]	= "rsa";
const xmlChar xmlSecNodeRSAKeyValue[]	= "RSAKeyValue";
const xmlChar xmlSecHrefRSAKeyValue[]	= "http://www.w3.org/2000/09/xmldsig#RSAKeyValue";

const char xmlSecNameRsaSha1[]		= "rsa-sha1";
const xmlChar xmlSecHrefRsaSha1[]	= "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

const char xmlSecNameRsaPkcs1[]		= "rsa-pkcs1";
const xmlChar xmlSecHrefRsaPkcs1[]	= "http://www.w3.org/2001/04/xmlenc#rsa-1_5";

const char xmlSecNameRsaOaep[]		= "rsa-oaep";
const xmlChar xmlSecHrefRsaOaep[]	= "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
const xmlChar xmlSecNodeRsaOAEPparams[]	= "OAEPparams";

/*************************************************************************
 *
 * SHA1 strings
 *
 ************************************************************************/
const char xmlSecNameSha1[]		= "sha1";
const xmlChar xmlSecHrefSha1[]		= "http://www.w3.org/2000/09/xmldsig#sha1";

/*************************************************************************
 *
 * X509 strings
 *
 ************************************************************************/
const char xmlSecNameX509Data[]		= "x509";
const xmlChar xmlSecNodeX509Data[]	= "X509Data";
const xmlChar xmlSecHrefX509Data[]	= "http://www.w3.org/2000/09/xmldsig#X509Data";

const char xmlSecNameRawX509Cert[]	= "raw-x509";
const xmlChar xmlSecHrefRawX509Cert[]	= "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";

/*************************************************************************
 *
 * Xslt strings
 *
 ************************************************************************/
const char xmlSecNameXslt[]		= "xslt";
const xmlChar xmlSecHrefXslt[]		= "http://www.w3.org/TR/1999/REC-xslt-19991116";

/*************************************************************************
 *
 * RetrievalMethod
 *
 ************************************************************************/
const char xmlSecNameRetrievalMethod[] 	= "retrieval-method";
const xmlChar xmlSecNodeRetrievalMethod[] = "RetrievalMethod";

/*************************************************************************
 *
 * EncryptedKey
 *
 ************************************************************************/
const char xmlSecNameEncryptedKey[]	= "enc-key";
const xmlChar xmlSecNodeEncryptedKey[]	= "EncryptedKey";
const xmlChar xmlSecHrefEncryptedKey[]	= "http://www.w3.org/2001/04/xmlenc#EncryptedKey";







const xmlChar xmlSecXPathNs[] 	= "http://www.w3.org/TR/1999/REC-xpath-19991116";
const xmlChar xmlSecXPath2Ns[] 	= "http://www.w3.org/2002/06/xmldsig-filter2";
const xmlChar xmlSecXPointerNs[]= "http://www.w3.org/2001/04/xmldsig-more/xptr";
