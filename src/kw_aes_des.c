/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Implementation of AES/DES Key Transport algorithm
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>

#include "kw_aes_des.h"


#ifndef XMLSEC_NO_AES
/********************************************************************
 *
 * KT AES
 *
 ********************************************************************/

/**
 * http://www.w3.org/TR/xmlenc-core/#sec-Alg-SymmetricKeyWrap:
 *
 * Assume that the data to be wrapped consists of N 64-bit data blocks
 * denoted P(1), P(2), P(3) ... P(N). The result of wrapping will be N+1
 * 64-bit blocks denoted C(0), C(1), C(2), ... C(N). The key encrypting
 * key is represented by K. Assume integers i, j, and t and intermediate
 * 64-bit register A, 128-bit register B, and array of 64-bit quantities
 * R(1) through R(N).
 *
 * "|" represents concatentation so x|y, where x and y and 64-bit quantities,
 * is the 128-bit quantity with x in the most significant bits and y in the
 * least significant bits. AES(K)enc(x) is the operation of AES encrypting
 * the 128-bit quantity x under the key K. AES(K)dec(x) is the corresponding
 * decryption opteration. XOR(x,y) is the bitwise exclusive or of x and y.
 * MSB(x) and LSB(y) are the most significant 64 bits and least significant
 * 64 bits of x and y respectively.
 *
 * If N is 1, a single AES operation is performed for wrap or unwrap.
 * If N>1, then 6*N AES operations are performed for wrap or unwrap.
 *
 * The key wrap algorithm is as follows:
 *
 *   1. If N is 1:
 *          * B=AES(K)enc(0xA6A6A6A6A6A6A6A6|P(1))
 *          * C(0)=MSB(B)
 *          * C(1)=LSB(B)
 *      If N>1, perform the following steps:
 *   2. Initialize variables:
 *          * Set A to 0xA6A6A6A6A6A6A6A6
 *          * Fori=1 to N,
 *            R(i)=P(i)
 *   3. Calculate intermediate values:
 *          * Forj=0 to 5,
 *                o For i=1 to N,
 *                  t= i + j*N
 *                  B=AES(K)enc(A|R(i))
 *                  A=XOR(t,MSB(B))
 *                  R(i)=LSB(B)
 *   4. Output the results:
 *          * Set C(0)=A
 *          * For i=1 to N,
 *            C(i)=R(i)
 *
 * The key unwrap algorithm is as follows:
 *
 *   1. If N is 1:
 *          * B=AES(K)dec(C(0)|C(1))
 *          * P(1)=LSB(B)
 *          * If MSB(B) is 0xA6A6A6A6A6A6A6A6, return success. Otherwise,
 *            return an integrity check failure error.
 *      If N>1, perform the following steps:
 *   2. Initialize the variables:
 *          * A=C(0)
 *          * For i=1 to N,
 *            R(i)=C(i)
 *   3. Calculate intermediate values:
 *          * For j=5 to 0,
 *                o For i=N to 1,
 *                  t= i + j*N
 *                  B=AES(K)dec(XOR(t,A)|R(i))
 *                  A=MSB(B)
 *                  R(i)=LSB(B)
 *   4. Output the results:
 *          * For i=1 to N,
 *            P(i)=R(i)
 *          * If A is 0xA6A6A6A6A6A6A6A6, return success. Otherwise, return
 *            an integrity check failure error.
 */
static const xmlSecByte xmlSecKWAesMagicBlock[XMLSEC_KW_AES_MAGIC_BLOCK_SIZE] = {
    0xA6,  0xA6,  0xA6,  0xA6,  0xA6,  0xA6,  0xA6,  0xA6
};

int
xmlSecKWAesEncode(xmlSecKWAesId kwAesId, void *context,
                  const xmlSecByte *in, xmlSecSize inSize,
                  xmlSecByte *out, xmlSecSize outSize) {
    xmlSecByte block[XMLSEC_KW_AES_BLOCK_SIZE];
    xmlSecByte *p;
    int N, i, j, t;
    int ret;

    xmlSecAssert2(kwAesId != NULL, -1);
    xmlSecAssert2(kwAesId->encrypt != NULL, -1);
    xmlSecAssert2(kwAesId->decrypt != NULL, -1);
    xmlSecAssert2(context != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize + XMLSEC_KW_AES_MAGIC_BLOCK_SIZE, -1);

    /* prepend magic block */
    if(in != out) {
        memcpy(out + XMLSEC_KW_AES_MAGIC_BLOCK_SIZE, in, inSize);
    } else {
        memmove(out + XMLSEC_KW_AES_MAGIC_BLOCK_SIZE, out, inSize);
    }
    memcpy(out, xmlSecKWAesMagicBlock, XMLSEC_KW_AES_MAGIC_BLOCK_SIZE);

    N = (inSize / 8);
    if(N == 1) {
        ret = kwAesId->encrypt(out, inSize + XMLSEC_KW_AES_MAGIC_BLOCK_SIZE, out, outSize, context);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "kwAesId->encrypt",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
    } else {
        for(j = 0; j <= 5; ++j) {
            for(i = 1; i <= N; ++i) {
                t = i + (j * N);
                p = out + i * 8;

                memcpy(block, out, 8);
                memcpy(block + 8, p, 8);

                ret = kwAesId->encrypt(block, sizeof(block), block, sizeof(block), context);
                if(ret < 0) {
                    xmlSecError(XMLSEC_ERRORS_HERE,
                                NULL,
                                "kwAesId->encrypt",
                                XMLSEC_ERRORS_R_XMLSEC_FAILED,
                                XMLSEC_ERRORS_NO_MESSAGE);
                    return(-1);
                }
                block[7] ^=  t;
                memcpy(out, block, 8);
                memcpy(p, block + 8, 8);
            }
        }
    }

    return(inSize + 8);
}

int
xmlSecKWAesDecode(xmlSecKWAesId kwAesId, void *context,
                  const xmlSecByte *in, xmlSecSize inSize,
                  xmlSecByte *out, xmlSecSize outSize) {
    xmlSecByte block[XMLSEC_KW_AES_BLOCK_SIZE];
    xmlSecByte *p;
    int N, i, j, t;
    int ret;

    xmlSecAssert2(kwAesId != NULL, -1);
    xmlSecAssert2(kwAesId->encrypt != NULL, -1);
    xmlSecAssert2(kwAesId->decrypt != NULL, -1);
    xmlSecAssert2(context != NULL, -1);
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(inSize > 0, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(outSize >= inSize, -1);

    /* copy input */
    if(in != out) {
        memcpy(out, in, inSize);
    }

    N = (inSize / 8) - 1;
    if(N == 1) {
        ret = kwAesId->decrypt(out, inSize, out, outSize, context);
        if(ret < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "kwAesId->decrypt",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
    } else {
        for(j = 5; j >= 0; --j) {
            for(i = N; i > 0; --i) {
                t = i + (j * N);
                p = out + i * 8;

                memcpy(block, out, 8);
                memcpy(block + 8, p, 8);
                block[7] ^= t;

                ret = kwAesId->decrypt(block, sizeof(block), block, sizeof(block), context);
                if(ret < 0) {
                    xmlSecError(XMLSEC_ERRORS_HERE,
                                NULL,
                                "kwAesId->decrypt",
                                XMLSEC_ERRORS_R_XMLSEC_FAILED,
                                XMLSEC_ERRORS_NO_MESSAGE);
                    return(-1);
                }
                memcpy(out, block, 8);
                memcpy(p, block + 8, 8);
            }
        }
    }
    /* do not left data in memory */
    memset(block, 0, sizeof(block));

    /* check the output */
    if(memcmp(xmlSecKWAesMagicBlock, out, XMLSEC_KW_AES_MAGIC_BLOCK_SIZE) != 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_DATA,
                    "bad magic block");
        return(-1);
    }

    /* get rid of magic block */
    memmove(out, out + XMLSEC_KW_AES_MAGIC_BLOCK_SIZE, inSize - XMLSEC_KW_AES_MAGIC_BLOCK_SIZE);
    return(inSize - XMLSEC_KW_AES_MAGIC_BLOCK_SIZE);
}

#endif /* XMLSEC_NO_AES */

