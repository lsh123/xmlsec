/** 
 * XMLSec library
 *
 *
 * See Copyright for the status of this software.
 * 
 * Author: Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysInternal.h>
#include <xmlsec/transforms.h>
#include <xmlsec/transformsInternal.h>
#include <xmlsec/io.h>
#include <xmlsec/errors.h>
#include <xmlsec/crypto.h>

const xmlChar xmlSecNs[] 	= "http://www.aleksey.com/xmlsec/2002";
const xmlChar xmlSecDSigNs[] 	= "http://www.w3.org/2000/09/xmldsig#";
const xmlChar xmlSecEncNs[] 	= "http://www.w3.org/2001/04/xmlenc#";
const xmlChar xmlSecXPathNs[] 	= "http://www.w3.org/TR/1999/REC-xpath-19991116";
const xmlChar xmlSecXPath2Ns[] 	= "http://www.w3.org/2002/06/xmldsig-filter2";
const xmlChar xmlSecXPointerNs[]= "http://www.w3.org/2001/04/xmldsig-more/xptr";
const xmlChar xmlExcC14NNs[] 	= "http://www.w3.org/2001/10/xml-exc-c14n#";
const xmlChar xmlExcC14NWithCommentsNs[] = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

const xmlChar xmlSecAesKeyValueName[] = "AESKeyValue";
const xmlChar xmlSecDesKeyValueName[] = "DESKeyValue";
const xmlChar xmlSecDsaKeyValueName[] = "DSAKeyValue";
const xmlChar xmlSecHmacKeyValueName[]= "HMACKeyValue";
const xmlChar xmlSecRsaKeyValueName[] = "RSAKeyValue";

const xmlChar xmlSecEncAes128CbcHref[] = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
const xmlChar xmlSecEncAes192CbcHref[] = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
const xmlChar xmlSecEncAes256CbcHref[] = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
const xmlChar xmlSecKWAes128CbcHref[]  = "http://www.w3.org/2001/04/xmlenc#kw-aes128";
const xmlChar xmlSecKWAes192CbcHref[]  = "http://www.w3.org/2001/04/xmlenc#kw-aes192";
const xmlChar xmlSecKWAes256CbcHref[]  = "http://www.w3.org/2001/04/xmlenc#kw-aes256";
const xmlChar xmlSecEncDes3CbcHref[]   = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
const xmlChar xmlSecKWDes3CbcHref[]    = "http://www.w3.org/2001/04/xmlenc#kw-tripledes";
const xmlChar xmlSecSignDsaSha1Href[]  = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
const xmlChar xmlSecMacHmacSha1Href[]  = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
const xmlChar xmlSecMacHmacMd5Href[]   = "http://www.w3.org/2001/04/xmldsig-more#hmac-md5";
const xmlChar xmlSecMacHmacRipeMd160Href[] = "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160";
const xmlChar xmlSecDigestRipemd160Href[]  = "http://www.w3.org/2001/04/xmlenc#ripemd160";
const xmlChar xmlSecSignRsaSha1Href[]  = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const xmlChar xmlSecEncRsaPkcs1Href[]  = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
const xmlChar xmlSecEncRsaOaepHref[]   = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
const xmlChar xmlSecDigestSha1Href[]   = "http://www.w3.org/2000/09/xmldsig#sha1";
const xmlChar xmlSecBase64DecodeHref[] = "http://www.w3.org/2000/09/xmldsig#base64";
const xmlChar xmlSecC14NInclusiveTransformHref[] = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const xmlChar xmlSecC14NInclusiveWithCommentsTransformHref[] = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
const xmlChar xmlSecC14NExclusiveTransformHref[] = "http://www.w3.org/2001/10/xml-exc-c14n#";
const xmlChar xmlSecC14NExclusiveWithCommentsTransformHref[] = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
const xmlChar xmlSecTransformEnvelopedHref[] 	= "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const xmlChar xmlSecXPathTransformHref[] 	= "http://www.w3.org/TR/1999/REC-xpath-19991116";
const xmlChar xmlSecXPath2TransformHref[] 	= "http://www.w3.org/2002/06/xmldsig-filter2";
const xmlChar xmlSecTransformXsltHref[]= "http://www.w3.org/TR/1999/REC-xslt-19991116";

/**
 * xmlSecInit:
 *
 * Initializes XML Security Library. The depended libraries
 * (LibXML, LibXSLT and Crypto engine) must be initialized before.
 */
int
xmlSecInit(void) {
    int ret;

    ret = xmlSecCryptoInit();
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecCryptoInit");
	return(-1);
    }
    xmlSecTransformIdsRegisterDefault();
    xmlSecKeyValueIdsRegisterDefault();
    xmlSecIOInit();
    return(0);
}

/**
 * xmlSecShutdown:
 *
 * Clean ups the XML Security Library.
 */
int 
xmlSecShutdown(void) {
    int ret;
    
    xmlSecIOShutdown();
    xmlSecKeyValueIdsUnregisterAll();
    xmlSecTransformIdsUnregisterAll();
    ret = xmlSecCryptoShutdown();
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecCryptoInit");
	return(-1);
    }
    return(0);
}

