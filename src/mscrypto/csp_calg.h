/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2005-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 * Copyright (c) 2005-2006 Cryptocom LTD (http://www.cryptocom.ru). All rights reserved.
 */
/**
 * @brief GOST cryptographic algorithm identifiers, CSP provider type IDs, and A/W CSP display-name macros for MSCrypto.
 */
#ifndef XMLSEC_MSCRYPTO_CSP_CALG_H
#define XMLSEC_MSCRYPTO_CSP_CALG_H

#include <windows.h>
#include <wincrypt.h>

#ifndef ALG_SID_GR3411
#  define ALG_SID_GR3411              30
#endif

#ifndef ALG_SID_GR3411_2012_256
#  define ALG_SID_GR3411_2012_256     33
#endif

#ifndef ALG_SID_GR3411_2012_512
#  define ALG_SID_GR3411_2012_512     34
#endif

#ifndef CALG_MAGPRO_HASH_R3411_94
#  define CALG_MAGPRO_HASH_R3411_94   (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411)
#endif

#ifndef CALG_GR3411_2012_256
#  define CALG_GR3411_2012_256        (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_256)
#endif

#ifndef CALG_GR3411_2012_512
#  define CALG_GR3411_2012_512        (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_512)
#endif

#ifndef PROV_MAGPRO_GOST
#  define PROV_MAGPRO_GOST            501
#endif
#define MAGPRO_CSP_A                "MagPro CSP"
#define MAGPRO_CSP_W                L"MagPro CSP"
#ifdef UNICODE
#define MAGPRO_CSP MAGPRO_CSP_W
#else
#define MAGPRO_CSP MAGPRO_CSP_A
#endif

#ifndef PROV_CRYPTOPRO_GOST
#  define PROV_CRYPTOPRO_GOST         75
#endif

#ifndef PROV_GOST_2012_256
#  define PROV_GOST_2012_256          80
#endif

#ifndef PROV_GOST_2012_512
#  define PROV_GOST_2012_512          81
#endif
#define CRYPTOPRO_CSP_A             "Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider"
#define CRYPTOPRO_CSP_W             L"Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider"
#define CRYPTOPRO_CSP_256_A         "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider"
#define CRYPTOPRO_CSP_256_W         L"Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider"
#define CRYPTOPRO_CSP_512_A         "Crypto-Pro GOST R 34.10-2012 Strong Cryptographic Service Provider"
#define CRYPTOPRO_CSP_512_W         L"Crypto-Pro GOST R 34.10-2012 Strong Cryptographic Service Provider"
#ifdef UNICODE
#define CRYPTOPRO_CSP CRYPTOPRO_CSP_W
#define CRYPTOPRO_CSP_256 CRYPTOPRO_CSP_256_W
#define CRYPTOPRO_CSP_512 CRYPTOPRO_CSP_512_W
#else
#define CRYPTOPRO_CSP CRYPTOPRO_CSP_A
#define CRYPTOPRO_CSP_256 CRYPTOPRO_CSP_256_A
#define CRYPTOPRO_CSP_512 CRYPTOPRO_CSP_512_A
#endif

#endif /* XMLSEC_MSCRYPTO_CSP_CALG_H */