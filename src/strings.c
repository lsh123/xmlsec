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
const xmlChar xmlSecNs[] 	= "http://www.aleksey.com/xmlsec/2002";
const xmlChar xmlSecDSigNs[] 	= "http://www.w3.org/2000/09/xmldsig#";
const xmlChar xmlSecEncNs[] 	= "http://www.w3.org/2001/04/xmlenc#";

/*************************************************************************
 *
 * AES strings
 *
 ************************************************************************/
const xmlChar xmlSecNameAESKeyValue[]	= "aes";
const xmlChar xmlSecNodeAESKeyValue[]	= "AESKeyValue";
const xmlChar xmlSecHrefAESKeyValue[]	= "http://www.aleksey.com/xmlsec/2002#AESKeyValue";

/*************************************************************************
 *
 * DES strings
 *
 ************************************************************************/
const xmlChar xmlSecNameDESKeyValue[]	= "des";
const xmlChar xmlSecNodeDESKeyValue[]	= "DESKeyValue";
const xmlChar xmlSecHrefDESKeyValue[]	= "http://www.aleksey.com/xmlsec/2002#DESKeyValue";

/*************************************************************************
 *
 * DSA strings
 *
 ************************************************************************/
const xmlChar xmlSecNameDSAKeyValue[]	= "dsa";
const xmlChar xmlSecNodeDSAKeyValue[]	= "DSAKeyValue";
const xmlChar xmlSecHrefDSAKeyValue[]	= "http://www.w3.org/2000/09/xmldsig#DSAKeyValue";

/*************************************************************************
 *
 * HMAC strings
 *
 ************************************************************************/
const xmlChar xmlSecNameHMACKeyValue[]	= "hmac";
const xmlChar xmlSecNodeHMACKeyValue[]	= "HMACKeyValue";
const xmlChar xmlSecHrefHMACKeyValue[]	= "http://www.aleksey.com/xmlsec/2002#HMACKeyValue";

/*************************************************************************
 *
 * RSA strings
 *
 ************************************************************************/
const xmlChar xmlSecNameRSAKeyValue[]	= "rsa";
const xmlChar xmlSecNodeRSAKeyValue[]	= "RSAKeyValue";
const xmlChar xmlSecHrefRSAKeyValue[]	= "http://www.w3.org/2000/09/xmldsig#RSAKeyValue";

/*************************************************************************
 *
 * X509 strings
 *
 ************************************************************************/
const xmlChar xmlSecNameX509Data[]	= "x509";
const xmlChar xmlSecNodeX509Data[]	= "X509Data";
const xmlChar xmlSecHrefX509Data[]	= "http://www.w3.org/2000/09/xmldsig#X509Data";

const xmlChar xmlSecNameRawX509Cert[]	= "raw-x509";
const xmlChar xmlSecHrefRawX509Cert[]	= "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";

/*************************************************************************
 *
 * RetrievalMethod
 *
 ************************************************************************/
const xmlChar xmlSecNameRetrievalMethod[] = "retrieval-method";
const xmlChar xmlSecNodeRetrievalMethod[] = "RetrievalMethod";

/*************************************************************************
 *
 * EncryptedKey
 *
 ************************************************************************/
const xmlChar xmlSecNameEncryptedKey[]	= "enc-key";
const xmlChar xmlSecNodeEncryptedKey[]	= "EncryptedKey";
const xmlChar xmlSecHrefEncryptedKey[]	= "http://www.w3.org/2001/04/xmlenc#EncryptedKey";










const xmlChar xmlSecXPathNs[] 	= "http://www.w3.org/TR/1999/REC-xpath-19991116";
const xmlChar xmlSecXPath2Ns[] 	= "http://www.w3.org/2002/06/xmldsig-filter2";
const xmlChar xmlSecXPointerNs[]= "http://www.w3.org/2001/04/xmldsig-more/xptr";
