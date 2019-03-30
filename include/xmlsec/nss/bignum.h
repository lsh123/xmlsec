/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Reading/writing BIGNUM values
 *
 * This is free software; see Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
#ifndef __XMLSEC_NSS_BIGNUM_H__
#define __XMLSEC_NSS_BIGNUM_H__

#include <libxml/tree.h>

#include <nspr.h>
#include <nss.h>

#include <xmlsec/xmlsec.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

XMLSEC_CRYPTO_EXPORT SECItem*   xmlSecNssNodeGetBigNumValue     (PRArenaPool *arena,
                                                                 const xmlNodePtr cur,
                                                                 SECItem *a);
XMLSEC_CRYPTO_EXPORT int        xmlSecNssNodeSetBigNumValue     (xmlNodePtr cur,
                                                                 const SECItem *a,
                                                                 int addLineBreaks);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_NSS_BIGNUM_H__ */

