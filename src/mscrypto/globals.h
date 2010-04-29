/*
 * XML Security Library
 *
 * THIS IS A PRIVATE XMLSEC HEADER FILE
 * DON'T USE IT IN YOUR APPLICATION
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2003 Cordys R&D BV, All rights reserved.
 */
#ifndef __XMLSEC_GLOBALS_H__
#define __XMLSEC_GLOBALS_H__

/**
 * Use autoconf defines if present.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#define IN_XMLSEC_CRYPTO
#define XMLSEC_PRIVATE

/* OpenSSL 0.9.6 and 0.9.7 do not have SHA 224/256/384/512 */
#if defined(XMLSEC_OPENSSL_096) || defined(XMLSEC_OPENSSL_097)
#define XMLSEC_NO_SHA224 1
#define XMLSEC_NO_SHA256 1
#define XMLSEC_NO_SHA384 1
#define XMLSEC_NO_SHA512 1
#endif /* defined(XMLSEC_OPENSSL_096) || defined(XMLSEC_OPENSSL_097) */

/* OpenSSL 0.9.6 does not have AES */
#if defined(XMLSEC_OPENSSL_096)
#define XMLSEC_NO_AES    1
#endif /* XMLSEC_OPENSSL_096 */


#endif /* ! __XMLSEC_GLOBALS_H__ */
