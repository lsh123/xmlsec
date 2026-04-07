/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * @brief Internal ASN1 helper functions for GCrypt.
 */
#ifndef __XMLSEC_GCRYPT_ASN1_H__
#define __XMLSEC_GCRYPT_ASN1_H__

#ifndef XMLSEC_PRIVATE
#error "gcrypt/asn1.h file contains private xmlsec-gcrypt definitions and should not be used outside xmlsec or xmlsec-$crypto libraries"
#endif /* XMLSEC_PRIVATE */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

enum xmlSecGCryptDerKeyType {
    xmlSecGCryptDerKeyTypeAuto = 0,
    xmlSecGCryptDerKeyTypePublicDsa,
    xmlSecGCryptDerKeyTypePrivateDsa,
    xmlSecGCryptDerKeyTypePublicRsa,
    xmlSecGCryptDerKeyTypePrivateRsa,
    xmlSecGCryptDerKeyTypePublicEc,
    xmlSecGCryptDerKeyTypePrivateEc
};

xmlSecKeyDataPtr        xmlSecGCryptParseDer            (const xmlSecByte * der,
                                                         xmlSecSize derlen,
                                                         enum xmlSecGCryptDerKeyType type);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /*__XMLSEC_GCRYPT_ASN1_H__ */
