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
#ifndef XMLSEC_GCRYPT_ASN1_H
#define XMLSEC_GCRYPT_ASN1_H

#ifndef XMLSEC_PRIVATE
#error "gcrypt/asn1.h file contains private xmlsec-gcrypt definitions and should not be used outside xmlsec or xmlsec-gcrypt libraries"
#endif /* XMLSEC_PRIVATE */


#include <xmlsec/exports.h>
#include <xmlsec/xmlsec.h>


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


#endif /* XMLSEC_GCRYPT_ASN1_H */
