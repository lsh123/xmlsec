/**
 * XMLSec library
 *
 * THIS IS A PRIVATE XMLSEC HEADER FILE
 * DON'T USE IT IN YOUR APPLICATION
 *
 * Implementation of AES/DES Key Transport algorithm
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2010 Aleksey Sanin, All rights reserved.
 */
#ifndef __XMLSEC_KT_AES_DES_H__
#define __XMLSEC_KT_AES_DES_H__

#ifndef XMLSEC_PRIVATE
#error "private.h file contains private xmlsec definitions and should not be used outside xmlsec or xmlsec-<crypto> libraries"
#endif /* XMLSEC_PRIVATE */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef XMLSEC_NO_AES
/********************************************************************
 *
 * KT AES
 *
 ********************************************************************/
#define XMLSEC_KW_AES_MAGIC_BLOCK_SIZE              8
#define XMLSEC_KW_AES_BLOCK_SIZE                    16
#define XMLSEC_KW_AES128_KEY_SIZE                   16
#define XMLSEC_KW_AES192_KEY_SIZE                   24
#define XMLSEC_KW_AES256_KEY_SIZE                   32

typedef int  (*xmlSecKWAesBlockEncryptMethod)       (const xmlSecByte * in,
                                                     xmlSecSize inSize,
                                                     xmlSecByte * out,
                                                     xmlSecSize outSize,
                                                     void * context);
typedef int  (*xmlSecKWAesBlockDecryptMethod)       (const xmlSecByte * in,
                                                     xmlSecSize inSize,
                                                     xmlSecByte * out,
                                                     xmlSecSize outSize,
                                                     void * context);


struct _xmlSecKWAesKlass {
    /* callbacks */
    xmlSecKWAesBlockEncryptMethod       encrypt;
    xmlSecKWAesBlockDecryptMethod       decrypt;

    /* for the future */
    void*                               reserved0;
    void*                               reserved1;
}; 
typedef const struct _xmlSecKWAesKlass              xmlSecKWAesKlass,
                                                    *xmlSecKWAesId;

XMLSEC_EXPORT int
xmlSecKWAesEncode(xmlSecKWAesId kwAesId, void *key,
                  const xmlSecByte *in, xmlSecSize inSize,
                  xmlSecByte *out, xmlSecSize outSize);

XMLSEC_EXPORT int
xmlSecKWAesDecode(xmlSecKWAesId kwAesId, void *key,
                  const xmlSecByte *in, xmlSecSize inSize,
                  xmlSecByte *out, xmlSecSize outSize);

#endif /* XMLSEC_NO_AES */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __XMLSEC_KT_AES_DES_H__ */
