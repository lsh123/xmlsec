/** 
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Tej Arora <tej@netscape.com>
 */
#ifndef __XMLSEC_NSS_PKIKEYS_H__
#define __XMLSEC_NSS_PKIKEYS_H__    

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>


XMLSEC_CRYPTO_EXPORT xmlSecKeyDataPtr 	xmlSecNssAdoptKey              (SECKEYPrivateKey *privkey,
									SECKEYPublicKey  *pubkey);

XMLSEC_CRYPTO_EXPORT SECKEYPublicKey*   xmlSecNssKeyDataGetPubKey	(xmlSecKeyDataPtr data);

XMLSEC_CRYPTO_EXPORT SECKEYPrivateKey*  xmlSecNssKeyDataGetPrivKey	(xmlSecKeyDataPtr data);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_NSS_PKIKEYS_H__ */


