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
#include <xmlsec/strings.h>

/* namespaces */
const xmlChar xmlSecNs[] 	= "http://www.aleksey.com/xmlsec/2002";
const xmlChar xmlSecNsDSig[] 	= "http://www.w3.org/2000/09/xmldsig#";
const xmlChar xmlSecNsEnc[] 	= "http://www.w3.org/2001/04/xmlenc#";
const xmlChar xmlSecNsXPath2[] 	= "http://www.w3.org/2002/06/xmldsig-filter2";
const xmlChar xmlSecNsXPointer[]= "http://www.w3.org/2001/04/xmldsig-more/xptr";
const xmlChar xmlSecNsExcC14N[]	= "http://www.w3.org/2001/10/xml-exc-c14n#";

/* KeyInfo children names */
const xmlChar xmlSecNameKeyName[]	= "KeyName";
const xmlChar xmlSecNameKeyValue[]	= "KeyValue";
const xmlChar xmlSecNameRetreivalMethod[] = "RetreivalMethod";
const xmlChar xmlSecNameX509Data[]	= "X509Data";
const xmlChar xmlSecNamePgpData[]	= "PGPData";
const xmlChar xmlSecNameSpkiData[]	= "SPKIData";
const xmlChar xmlSecNameMgmtData[]	= "MgmtData";

/* KeyValue childs */
const xmlChar xmlSecNameAesKeyValue[] 	= "AESKeyValue";
const xmlChar xmlSecNameDesKeyValue[] 	= "DESKeyValue";
const xmlChar xmlSecNameDsaKeyValue[] 	= "DSAKeyValue";
const xmlChar xmlSecNameHmacKeyValue[]	= "HMACKeyValue";
const xmlChar xmlSecNameRsaKeyValue[] 	= "RSAKeyValue";

/* RetrievalMethod hrefs */
const xmlChar xmlSecHrefRetrievalMethodTypeDSAKeyValue[] = "http://www.w3.org/2000/09/xmldsig#DSAKeyValue";
const xmlChar xmlSecHrefRetrievalMethodTypeRSAKeyValue[] = "http://www.w3.org/2000/09/xmldsig#RSAKeyValue";
const xmlChar xmlSecHrefRetrievalMethodTypeX509Data[] 	 = "http://www.w3.org/2000/09/xmldsig#X509Data";
const xmlChar xmlSecHrefRetrievalMethodTypePGPData[] 	 = "http://www.w3.org/2000/09/xmldsig#PGPData";
const xmlChar xmlSecHrefRetrievalMethodTypeSPKIData[] 	 = "http://www.w3.org/2000/09/xmldsig#SPKIData";
const xmlChar xmlSecHrefRetrievalMethodTypeMgmtData[] 	 = "http://www.w3.org/2000/09/xmldsig#MgmtData";
const xmlChar xmlSecHrefRetrievalMethodTypeRawX509Cert[] = "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";

/* base64 */
const xmlChar xmlSecHrefBase64Decode[] = "http://www.w3.org/2000/09/xmldsig#base64";

/* c14n algorithms hrefs */
const xmlChar xmlSecHrefC14NInclusiveTransform[] = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const xmlChar xmlSecHrefC14NInclusiveWithCommentsTransform[] = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
const xmlChar xmlSecHrefC14NExclusiveTransform[] = "http://www.w3.org/2001/10/xml-exc-c14n#";
const xmlChar xmlSecHrefC14NExclusiveWithCommentsTransform[] = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

/* xml transforms hrefs */
const xmlChar xmlSecHrefTransformEnveloped[] 	= "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const xmlChar xmlSecHrefXPathTransform[] 	= "http://www.w3.org/TR/1999/REC-xpath-19991116";
const xmlChar xmlSecHrefXPath2Transform[] 	= "http://www.w3.org/2002/06/xmldsig-filter2";
const xmlChar xmlSecHrefTransformXslt[]		= "http://www.w3.org/TR/1999/REC-xslt-19991116";

/* digests algorithms hrefs */
const xmlChar xmlSecHrefDigestRipemd160[]  	= "http://www.w3.org/2001/04/xmlenc#ripemd160";
const xmlChar xmlSecHrefDigestSha1[]   		= "http://www.w3.org/2000/09/xmldsig#sha1";

/* signature algorithm hrefs */
const xmlChar xmlSecHrefSignDsaSha1[]  = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
const xmlChar xmlSecHrefSignRsaSha1[]  = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const xmlChar xmlSecHrefMacHmacSha1[]  = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
const xmlChar xmlSecHrefMacHmacMd5[]   = "http://www.w3.org/2001/04/xmldsig-more#hmac-md5";
const xmlChar xmlSecHrefMacHmacRipeMd160[] = "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160";

/* encryption algorithms hrefs */
const xmlChar xmlSecHrefEncAes128Cbc[] = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
const xmlChar xmlSecHrefEncAes192Cbc[] = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
const xmlChar xmlSecHrefEncAes256Cbc[] = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
const xmlChar xmlSecHrefEncDes3Cbc[]   = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
const xmlChar xmlSecHrefEncRsaPkcs1[]  = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
const xmlChar xmlSecHrefEncRsaOaep[]   = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

/* key wrap algorithm hrefs */
const xmlChar xmlSecHrefKWAes128Cbc[]  = "http://www.w3.org/2001/04/xmlenc#kw-aes128";
const xmlChar xmlSecHrefKWAes192Cbc[]  = "http://www.w3.org/2001/04/xmlenc#kw-aes192";
const xmlChar xmlSecHrefKWAes256Cbc[]  = "http://www.w3.org/2001/04/xmlenc#kw-aes256";
const xmlChar xmlSecHrefKWDes3Cbc[]    = "http://www.w3.org/2001/04/xmlenc#kw-tripledes";

			    
