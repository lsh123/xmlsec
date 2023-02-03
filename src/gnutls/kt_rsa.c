/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2022 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:kt_rsa
 * @Short_description: RSA Key Transport transforms implementation for GnuTLS.
 * @Stability: Private
 *
 */

#ifndef XMLSEC_NO_RSA
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/gnutls/crypto.h>

/**************************************************************************
 *
 * We use xmlsec-gcrypt for all the basic crypto ops
 *
 *****************************************************************************/
#include <xmlsec/gcrypt/crypto.h>

/**
 * xmlSecGnuTLSTransformRsaPkcs1GetKlass:
 *
 * The RSA-PKCS1 key transport transform klass.
 *
 * Returns: RSA-PKCS1 key transport transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaPkcs1GetKlass(void) {
    return(xmlSecGCryptTransformRsaPkcs1GetKlass());
}

/**
 * xmlSecGnuTLSTransformRsaOaepGetKlass:
 *
 * The RSA-OAEP key transport transform klass (XMLEnc 1.0).
 *
 * Returns: RSA-OAEP key transport transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaOaepGetKlass(void) {
    return(xmlSecGCryptTransformRsaOaepGetKlass());
}

/**
 * xmlSecGnuTLSTransformRsaOaepEnc11GetKlass:
 *
 * The RSA-OAEP key transport transform klass (XMLEnc 1.1).
 *
 * Returns: RSA-OAEP key transport transform klass.
 */
xmlSecTransformId
xmlSecGnuTLSTransformRsaOaepEnc11GetKlass(void) {
    return(xmlSecGCryptTransformRsaOaepEnc11GetKlass());
}

#else /* XMLSEC_NO_RSA */

/* ISO C forbids an empty translation unit */
typedef int make_iso_compilers_happy;

#endif /* XMLSEC_NO_RSA */
