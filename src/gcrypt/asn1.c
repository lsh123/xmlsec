/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * ASN1 support functions for GCrypt.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
/**
 * SECTION:crypto
 */

#include "globals.h"

#include <string.h>

#include <gcrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>

#include <xmlsec/gcrypt/crypto.h>

#include "asn1.h"
#include "../cast_helpers.h"

/**************************************************************************
 *
 * ASN.1 parser is taken from GCrypt tests
 *
 *************************************************************************/

/* ASN.1 classes.  */
enum
{
  UNIVERSAL = 0,
  APPLICATION = 1,
  ASNCONTEXT = 2,
  PRIVATE = 3
};


/* ASN.1 tags.  */
enum
{
  TAG_NONE = 0,
  TAG_BOOLEAN = 1,
  TAG_INTEGER = 2,
  TAG_BIT_STRING = 3,
  TAG_OCTET_STRING = 4,
  TAG_NULL = 5,
  TAG_OBJECT_ID = 6,
  TAG_OBJECT_DESCRIPTOR = 7,
  TAG_EXTERNAL = 8,
  TAG_REAL = 9,
  TAG_ENUMERATED = 10,
  TAG_EMBEDDED_PDV = 11,
  TAG_UTF8_STRING = 12,
  TAG_REALTIVE_OID = 13,
  TAG_SEQUENCE = 16,
  TAG_SET = 17,
  TAG_NUMERIC_STRING = 18,
  TAG_PRINTABLE_STRING = 19,
  TAG_TELETEX_STRING = 20,
  TAG_VIDEOTEX_STRING = 21,
  TAG_IA5_STRING = 22,
  TAG_UTC_TIME = 23,
  TAG_GENERALIZED_TIME = 24,
  TAG_GRAPHIC_STRING = 25,
  TAG_VISIBLE_STRING = 26,
  TAG_GENERAL_STRING = 27,
  TAG_UNIVERSAL_STRING = 28,
  TAG_CHARACTER_STRING = 29,
  TAG_BMP_STRING = 30
};

/* ASN.1 Parser object.  */
struct tag_info
{
  int class;             /* Object class.  */
  unsigned long tag;     /* The tag of the object.  */
  unsigned long length;  /* Length of the values.  */
  int nhdr;              /* Length of the header (TL).  */
  unsigned int ndef:1;   /* The object has an indefinite length.  */
  unsigned int cons:1;   /* This is a constructed object.  */
};

/* Parse the buffer at the address BUFFER which consists of the number
   of octets as stored at BUFLEN.  Return the tag and the length part
   from the TLV triplet.  Update BUFFER and BUFLEN on success.  Checks
   that the encoded length does not exhaust the length of the provided
   buffer. */
static int
xmlSecGCryptAsn1ParseTag (xmlSecByte const **buffer, unsigned long *buflen, struct tag_info *ti)
{
    unsigned long c;
    unsigned long tag;
    const xmlSecByte *buf;
    unsigned long length;

    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2((*buffer) != NULL, -1);
    xmlSecAssert2(buflen != NULL, -1);
    xmlSecAssert2(ti != NULL, -1);

    /* initialize */
    buf = *buffer;
    length = *buflen;

    ti->length = 0;
    ti->ndef = 0;
    ti->nhdr = 0;

    /* Get the tag */
    if (length <= 0) {
        return(-1); /* Premature EOF.  */
    }
    c = *buf++;
    length--;
    ti->nhdr++;

    ti->class = (c & 0xc0) >> 6;
    ti->cons  = !!(c & 0x20);
    tag       = (c & 0x1f);

    if (tag == 0x1f) {
        tag = 0;
        do {
            tag <<= 7;
            if (length <= 0) {
                return(-1); /* Premature EOF.  */
            }
            c = *buf++;
            length--;
            ti->nhdr++;
            tag |= (c & 0x7f);
        } while ( (c & 0x80) );
    }
    ti->tag = tag;

    /* Get the length */
    if(length <= 0) {
        return -1; /* Premature EOF. */
    }
    c = *buf++;
    length--;
    ti->nhdr++;

    if ( !(c & 0x80) ) {
        ti->length = c;
    } else if (c == 0x80) {
        ti->ndef = 1;
    } else if (c == 0xff) {
        return -1; /* Forbidden length value.  */
    } else {
        unsigned long len = 0;
        int count = c & 0x7f;

        for (; count; count--) {
            len <<= 8;
            if (length <= 0) {
                return -1; /* Premature EOF.  */
            }
            c = *buf++; length--;
            ti->nhdr++;
            len |= (c & 0xff);
        }
        ti->length = len;
    }

    if (ti->class == UNIVERSAL && !ti->tag) {
        ti->length = 0;
    }

    if (ti->length > length) {
        return(-1); /* Data larger than buffer.  */
    }

    /* done */
    *buffer = buf;
    *buflen = length;
    return(0);
}

#define XMLSEC_GCRYPT_ASN1_MAX_OBJECT_ID_SIZE    32
typedef xmlSecByte xmlSecGCryptAsn1ObjectId[XMLSEC_GCRYPT_ASN1_MAX_OBJECT_ID_SIZE];

typedef struct _xmlSecGCryptAsn1EcObjectIdToCurve {
    char curve[20];
    xmlSecGCryptAsn1ObjectId objectId;
} xmlSecGCryptAsn1EcObjectIdToCurve;

static xmlSecGCryptAsn1EcObjectIdToCurve g_xmlSecGCryptAsn1EcObjectIdToCurves[] = {
    { "prime192v1",     { 0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x01 } }, /* OBJ_X9_62_prime192v1 */
    { "secp224r1",      { 0x2B,0x81,0x04,0x00,0x21,0x00,0x00,0x00 } }, /* OBJ_secp224r1 */
    { "prime256v1",     { 0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07 } }, /* OBJ_X9_62_prime256v1 */
    { "secp384r1",      { 0x2B,0x81,0x04,0x00,0x22,0x00,0x00,0x00 } }, /* OBJ_secp384r1 */
    { "secp521r1",      { 0x2B,0x81,0x04,0x00,0x23,0x00,0x00,0x00 } }, /* OBJ_secp521r1 */
};

static const char*
xmlSecGCryptAsn1GetCurveFromObjectId(xmlSecGCryptAsn1ObjectId objectid) {
    int size = sizeof(g_xmlSecGCryptAsn1EcObjectIdToCurves) / sizeof(g_xmlSecGCryptAsn1EcObjectIdToCurves[0]);
    int ii;
    for(ii = 0; ii < size; ++ii) {
        if(memcmp(objectid, g_xmlSecGCryptAsn1EcObjectIdToCurves[ii].objectId, XMLSEC_GCRYPT_ASN1_MAX_OBJECT_ID_SIZE) == 0) {
            return(g_xmlSecGCryptAsn1EcObjectIdToCurves[ii].curve);
        }
    }
    return(NULL);
}

static int
xmlSecGCryptAsn1IsECKey(xmlSecGCryptAsn1ObjectId * objectids, xmlSecSize objectids_num) {
    const char* ecCurve = NULL;
    xmlSecAssert2(objectids != NULL, xmlSecGCryptDerKeyTypeAuto);

    /* EC key should have the curve object id */
    for(xmlSecSize ii = 0; (ii < objectids_num) && (ecCurve == NULL); ++ii) {
        ecCurve = xmlSecGCryptAsn1GetCurveFromObjectId(objectids[ii]);
    }
    return(ecCurve != NULL ? 1 : 0);
}


static int
xmlSecGCryptAsn1ParseIntegerSequence(int level, xmlSecByte const **buffer, xmlSecSize* buflen,
    gcry_mpi_t * integers, xmlSecSize integers_size, xmlSecSize * integers_out_size,
    xmlSecGCryptAsn1ObjectId * objectids, xmlSecSize objectids_size, xmlSecSize * objectids_out_size)
{
    const xmlSecByte *buf;
    unsigned long length;
    struct tag_info ti;
    gcry_error_t err;
    int idx = 0;
    int ret;

    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2((*buffer) != NULL, -1);
    xmlSecAssert2(buflen != NULL, -1);
    xmlSecAssert2(integers != NULL, -1);
    xmlSecAssert2(integers_size > 0, -1);
    xmlSecAssert2(integers_out_size != NULL, -1);
    xmlSecAssert2(objectids != NULL, -1);
    xmlSecAssert2(objectids_size > 0, -1);
    xmlSecAssert2(objectids_out_size != NULL, -1);

    /* initialize */
    buf = *buffer;
    XMLSEC_SAFE_CAST_SIZE_TO_ULONG((*buflen), length, return(-1), NULL);

    /* read SEQUENCE */
    memset(&ti, 0, sizeof(ti));

    if(level == 0) {
        ret = xmlSecGCryptAsn1ParseTag (&buf, &length, &ti);
        if((ret != 0)  || (ti.tag != TAG_SEQUENCE) || ti.class || !ti.cons || ti.ndef) {
            xmlSecInternalError2("xmlSecGCryptAsn1ParseTag", NULL,
                "TAG_SEQUENCE is expected: tag=%lu", ti.tag);
            return(-1);
        }
    }

    /* read sequence */
    for (idx = 0;  (length > 0); idx++) {
        memset(&ti, 0, sizeof(ti));
        ret = xmlSecGCryptAsn1ParseTag (&buf, &length, &ti);
        if((ret != 0) || (ti.ndef != 0)) {
            xmlSecInternalError2("xmlSecGCryptAsn1ParseTag", NULL, "index=%d", idx);
            return(-1);
        }

        if(ti.cons != 0) {
            const xmlSecByte* buf2 = buf;
            xmlSecSize buf2len;

            XMLSEC_SAFE_CAST_ULONG_TO_SIZE(ti.length, buf2len, return(-1), NULL);
            ret = xmlSecGCryptAsn1ParseIntegerSequence(
                    level + 1, &buf2, &buf2len,
                    integers, integers_size, integers_out_size,
                    objectids, objectids_size, objectids_out_size);
            if(ret != 0) {
                xmlSecInternalError3("xmlSecGCryptAsn1ParseIntegerSequence", NULL, "level=%d, index=%d", level, idx);
                return(-1);
            }
        } else {
            switch(ti.tag) {
                case TAG_BIT_STRING:
                case TAG_INTEGER:
                case TAG_OCTET_STRING:
                    if((*integers_out_size) >= integers_size) {
                        xmlSecInternalError2("xmlSecGCryptAsn1ParseTag", NULL, "sequence too long, integers_size=" XMLSEC_SIZE_FMT, integers_size);
                        return(-1);
                    }

                    /* HACK HACK HACK: DSA pubkey has a TAG_BIT_STRING for public exp (y) that has 4 bytes in front
                     * this is likely going to break something. Note that EC keys also use BIT_STRING but there is no prefixes
                     */
                    if((ti.tag == TAG_BIT_STRING) && (ti.length >= 4) && (xmlSecGCryptAsn1IsECKey(objectids, *objectids_out_size) == 0)) {
                        ti.length -= 4;
                        length -= 4;
                        buf += 4;
                    }
                    err = gcry_mpi_scan(&(integers[(*integers_out_size)]), GCRYMPI_FMT_USG, buf, ti.length, NULL);
                    if((err != GPG_ERR_NO_ERROR) || (integers[(*integers_out_size)] == NULL)) {
                        xmlSecGCryptError("gcry_mpi_scan", err, NULL);
                        return(-1);
                    }
                    ++(*integers_out_size);
                    break;

                case TAG_OBJECT_ID:
                    if((*objectids_out_size) >= objectids_size) {
                        xmlSecInternalError2("xmlSecGCryptAsn1ParseTag", NULL, "sequence too long, objectids_size=" XMLSEC_SIZE_FMT, objectids_size);
                        return(-1);
                    }
                    if(ti.length > XMLSEC_GCRYPT_ASN1_MAX_OBJECT_ID_SIZE) {
                        xmlSecInternalError2("xmlSecGCryptAsn1ParseTag", NULL, "object id too long, len=%lu", ti.length);
                        return(-1);
                    }
                    memcpy(objectids[(*objectids_out_size)], buf, ti.length);
                    ++(*objectids_out_size);
                    break;

                case TAG_NULL:
                    /* do nothing */
                    break;

                default:
                    xmlSecInternalError3("xmlSecGCryptAsn1ParseTag", NULL,
                        "Unexpected ASN1 tag=%lu at index=%d", ti.tag, idx);
                    return(-1);
            }
        }

        buf += ti.length;
        length -= ti.length;
    }

    /* done */
    *buffer = buf;
    XMLSEC_SAFE_CAST_ULONG_TO_SIZE(length, (*buflen), return(-1), NULL);
    return(0);
}

/* expected number of integers for various keys */
#define XMLSEC_GNUTLS_ASN1_DSA_PUB_NUM          4U
#define XMLSEC_GNUTLS_ASN1_DSA_PRIV_NUM         6U

#define XMLSEC_GNUTLS_ASN1_EDCSA_PUB_NUM        1U
#define XMLSEC_GNUTLS_ASN1_EDCSA_PRIV_NUM       3U

#define XMLSEC_GNUTLS_ASN1_RSA_PUB_NUM          2U
#define XMLSEC_GNUTLS_ASN1_RSA_PRIV_NUM         9U

static enum xmlSecGCryptDerKeyType
xmlSecGCryptAsn1GuessKeyType(gcry_mpi_t * integers, xmlSecSize integers_num, xmlSecGCryptAsn1ObjectId * objectids, xmlSecSize objectids_num) {
    xmlSecAssert2(integers != NULL, xmlSecGCryptDerKeyTypeAuto);
    xmlSecAssert2(objectids != NULL, xmlSecGCryptDerKeyTypeAuto);

    /* EC key should have the curve object id */
    if(xmlSecGCryptAsn1IsECKey(objectids, objectids_num) != 0) {
        if(integers_num >= XMLSEC_GNUTLS_ASN1_EDCSA_PRIV_NUM) {
            return(xmlSecGCryptDerKeyTypePrivateEc);
        } else if(integers_num >= XMLSEC_GNUTLS_ASN1_EDCSA_PUB_NUM) {
            return(xmlSecGCryptDerKeyTypePublicEc);
        } else {
            return(xmlSecGCryptDerKeyTypeAuto);
        }
    }

    /* try other keys */
    switch(integers_num) {
    case XMLSEC_GNUTLS_ASN1_DSA_PUB_NUM:
        return(xmlSecGCryptDerKeyTypePublicDsa);
    case XMLSEC_GNUTLS_ASN1_DSA_PRIV_NUM:
        return(xmlSecGCryptDerKeyTypePrivateDsa);

    case XMLSEC_GNUTLS_ASN1_RSA_PUB_NUM:
        return(xmlSecGCryptDerKeyTypePublicRsa);
    case XMLSEC_GNUTLS_ASN1_RSA_PRIV_NUM:
        return(xmlSecGCryptDerKeyTypePrivateRsa);
    default:
        return(xmlSecGCryptDerKeyTypeAuto);
    }
}

xmlSecKeyDataPtr
xmlSecGCryptParseDer(const xmlSecByte * der, xmlSecSize derlen,
                     enum xmlSecGCryptDerKeyType type) {
    xmlSecKeyDataPtr key_data = NULL;
    gcry_sexp_t s_pub_key = NULL;
    gcry_sexp_t s_priv_key = NULL;
    gcry_error_t err;
    gcry_mpi_t integers[20];
    xmlSecSize integers_num = 0;
    xmlSecGCryptAsn1ObjectId objectids[20];
    xmlSecSize objectids_num = 0;
    unsigned int idx;
    const char* ecCurve = NULL;
    int ret;

    xmlSecAssert2(der != NULL, NULL);
    xmlSecAssert2(derlen > 0, NULL);

    /* Parse the ASN.1 structure.  */
    memset(&integers, 0, sizeof(integers));
    memset(&objectids, 0, sizeof(objectids));
    ret = xmlSecGCryptAsn1ParseIntegerSequence(
        0, &der, &derlen,
        integers,  sizeof(integers) / sizeof(integers[0]), &integers_num,
        objectids,  sizeof(objectids) / sizeof(objectids[0]), &objectids_num
    );
    if(ret < 0) {
        xmlSecInternalError("xmlSecGCryptAsn1ParseIntegerSequence", NULL);
        goto done;
    }

    /* do we need to guess the key type? not robust but the best we can do */
    if(type == xmlSecGCryptDerKeyTypeAuto) {
        type = xmlSecGCryptAsn1GuessKeyType(integers, integers_num, objectids, objectids_num);
        if(type == xmlSecGCryptDerKeyTypeAuto) {
            /* unknown */
            xmlSecInvalidSizeDataError("integers_num", integers_num,
                "the number of parameters matching key type", NULL);
            goto done;
        }
    }

    switch(type) {
#ifndef XMLSEC_NO_DSA
    case xmlSecGCryptDerKeyTypePrivateDsa:
        /* check we have enough integers */
        if(integers_num != XMLSEC_GNUTLS_ASN1_DSA_PRIV_NUM) {
            xmlSecInvalidSizeError("Private DSA key params",
                integers_num, (xmlSecSize)XMLSEC_GNUTLS_ASN1_DSA_PRIV_NUM, NULL);
            goto done;
        }

        /* first is always 0, ignore */

        /* Convert from OpenSSL parameter ordering to the OpenPGP order. */
        /* First check that x < y; if not swap x and y  */
        if (gcry_mpi_cmp (integers[4], integers[5]) > 0) {
            gcry_mpi_swap (integers[4], integers[5]);
        }

        /* Build the S-expressions  */
        /* order in the DER file: p, q, g, y, x */
        err = gcry_sexp_build (&s_priv_key, NULL,
                "(private-key(dsa(p%m)(q%m)(g%m)(x%m)(y%m)))",
                integers[1], integers[2], integers[3], integers[4], integers[5]
        );
        if((err != GPG_ERR_NO_ERROR) || (s_priv_key == NULL)) {
            xmlSecGCryptError("gcry_sexp_build(private-key/dsa)", err, NULL);
            goto done;
        }

        err = gcry_sexp_build (&s_pub_key, NULL,
                "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
                integers[1], integers[2], integers[3], integers[5]
        );
        if((err != GPG_ERR_NO_ERROR) || (s_pub_key == NULL)) {
            xmlSecGCryptError("gcry_sexp_build(public-key/dsa)", err, NULL);
            goto done;
        }

        /* construct key and key data */
        key_data = xmlSecKeyDataCreate(xmlSecGCryptKeyDataDsaId);
        if(key_data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(xmlSecGCryptKeyDataDsaId)", NULL);
            goto done;
        }

        ret = xmlSecGCryptKeyDataDsaAdoptKeyPair(key_data, s_pub_key, s_priv_key);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGCryptKeyDataDsaAdoptKey(xmlSecGCryptKeyDataDsaId)", NULL);
            xmlSecKeyDataDestroy(key_data);
            key_data = NULL;
            goto done;
        }
        s_pub_key = NULL; /* owned by key_data now */
        s_priv_key = NULL; /* owned by key_data now */
        break;

    case xmlSecGCryptDerKeyTypePublicDsa:
        /* check we have enough integers */
        if(integers_num != XMLSEC_GNUTLS_ASN1_DSA_PUB_NUM) {
            xmlSecInvalidSizeError("Public DSA key params",
                integers_num, (xmlSecSize)XMLSEC_GNUTLS_ASN1_DSA_PUB_NUM, NULL);
            goto done;
        }

        /* Build the S-expression.  */
        /* order in the DER file: p, q, g, y */
        err = gcry_sexp_build (&s_pub_key, NULL,
                "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
                integers[0], integers[1], integers[2], integers[3]
        );
        if((err != GPG_ERR_NO_ERROR) || (s_pub_key == NULL)) {
            xmlSecGCryptError("gcry_sexp_build(public-key/dsa)", err, NULL);
            goto done;
        }

        /* construct key and key data */
        key_data = xmlSecKeyDataCreate(xmlSecGCryptKeyDataDsaId);
        if(key_data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(xmlSecGCryptKeyDataDsaId)", NULL);
            goto done;
        }

        ret = xmlSecGCryptKeyDataDsaAdoptKeyPair(key_data, s_pub_key, NULL);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGCryptKeyDataDsaAdoptKey(xmlSecGCryptKeyDataDsaId)", NULL);
            xmlSecKeyDataDestroy(key_data);
            key_data = NULL;
            goto done;
        }
        s_pub_key = NULL; /* owned by key_data now */
        break;
#endif /* XMLSEC_NO_DSA */

#ifndef XMLSEC_NO_RSA
    case xmlSecGCryptDerKeyTypePrivateRsa:
        /* check we have enough integers */
        if(integers_num < XMLSEC_GNUTLS_ASN1_RSA_PRIV_NUM) {
            xmlSecInvalidSizeError("Private RSA key params",
                (xmlSecSize)integers_num, (xmlSecSize)XMLSEC_GNUTLS_ASN1_RSA_PRIV_NUM, NULL);
            goto done;
        }

        /* first integer is 0, just skip it */

        /* Build the S-expression.  */
        err = gcry_sexp_build (&s_priv_key, NULL,
                         "(private-key(rsa(n%m)(e%m)(d%m)))",
                         integers[1], integers[2], integers[3]
        );
        if((err != GPG_ERR_NO_ERROR) || (s_priv_key == NULL)) {
            xmlSecGCryptError("gcry_sexp_build(private-key/rsa)", err, NULL);
            goto done;
        }

        err = gcry_sexp_build (&s_pub_key, NULL,
                         "(public-key(rsa(n%m)(e%m)))",
                         integers[1], integers[2]
        );
        if((err != GPG_ERR_NO_ERROR) || (s_pub_key == NULL)) {
            xmlSecGCryptError("gcry_sexp_build(public-key/rsa)", err, NULL);
            goto done;
        }

        /* construct key and key data */
        key_data = xmlSecKeyDataCreate(xmlSecGCryptKeyDataRsaId);
        if(key_data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(xmlSecGCryptKeyDataRsaId)", NULL);
            goto done;
        }

        ret = xmlSecGCryptKeyDataRsaAdoptKeyPair(key_data, s_pub_key, s_priv_key);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGCryptKeyDataRsaAdoptKey(xmlSecGCryptKeyDataRsaId)", NULL);
            xmlSecKeyDataDestroy(key_data);
            key_data = NULL;
            goto done;
        }
        s_pub_key = NULL; /* owned by key_data now */
        s_priv_key = NULL; /* owned by key_data now */
        break;

    case xmlSecGCryptDerKeyTypePublicRsa:
        /* check we have enough integers */
        if(integers_num != XMLSEC_GNUTLS_ASN1_RSA_PUB_NUM) {
            xmlSecInvalidSizeError("Public RSA key params",
                integers_num, (xmlSecSize)XMLSEC_GNUTLS_ASN1_RSA_PUB_NUM, NULL);
            goto done;
        }

        /* Build the S-expression.  */
        err = gcry_sexp_build (&s_pub_key, NULL,
                         "(public-key(rsa(n%m)(e%m)))",
                         integers[0], integers[1]
        );
        if((err != GPG_ERR_NO_ERROR) || (s_pub_key == NULL)) {
            xmlSecGCryptError("gcry_sexp_build(public-key/rsa)", err, NULL);
            goto done;
        }

        /* construct key and key data */
        key_data = xmlSecKeyDataCreate(xmlSecGCryptKeyDataRsaId);
        if(key_data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(xmlSecGCryptKeyDataRsaId)", NULL);
            goto done;
        }

        ret = xmlSecGCryptKeyDataRsaAdoptKeyPair(key_data, s_pub_key, NULL);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGCryptKeyDataRsaAdoptKey(xmlSecGCryptKeyDataRsaId)", NULL);
            xmlSecKeyDataDestroy(key_data);
            key_data = NULL;
            goto done;
        }
        s_pub_key = NULL; /* owned by key_data now */
        break;
#endif /* XMLSEC_NO_RSA */

#ifndef XMLSEC_NO_EC
    case xmlSecGCryptDerKeyTypePrivateEc:
        /* check we have object id and enough integers */
        if(objectids_num < 1U) {
            xmlSecInvalidSizeError("Private EC requires object ID for curve",
                (xmlSecSize)objectids_num, (xmlSecSize)1U, NULL);
            goto done;
        }
        if(integers_num < XMLSEC_GNUTLS_ASN1_EDCSA_PRIV_NUM) {
            xmlSecInvalidSizeError("Private EC key params",
                (xmlSecSize)integers_num, (xmlSecSize)XMLSEC_GNUTLS_ASN1_EDCSA_PRIV_NUM, NULL);
            goto done;
        }

        /* first integer is 0, just skip it */

        /* search through all object ids to find the curve name */
        for(xmlSecSize ii = 0; (ii < objectids_num) && (ecCurve == NULL); ++ii) {
            ecCurve = xmlSecGCryptAsn1GetCurveFromObjectId(objectids[ii]);
        }
        if(ecCurve == NULL) {
            xmlSecInvalidDataError("Unknown EC curve Object ID", NULL);
            goto done;
        }

        /* Build the S-expression.  */
        err = gcry_sexp_build (&s_priv_key, NULL,
            "(private-key (ecdsa"
            " (curve %s)"
            " (d %m)"
            " (q %m)"
            " ))",
            ecCurve, integers[1], integers[2]
        );
        if((err != GPG_ERR_NO_ERROR) || (s_priv_key == NULL)) {
            xmlSecGCryptError("gcry_sexp_build(private-key/ecdsa)", err, NULL);
            goto done;
        }

        err = gcry_sexp_build (&s_pub_key, NULL,
            "(public-key (ecdsa"
            " (curve %s)"
            " (q %m)"
            " ))",
            ecCurve, integers[2]
        );
        if((err != GPG_ERR_NO_ERROR) || (s_pub_key == NULL)) {
            xmlSecGCryptError("gcry_sexp_build(public-key/ecdsa)", err, NULL);
            goto done;
        }

        /* construct key and key data */
        key_data = xmlSecKeyDataCreate(xmlSecGCryptKeyDataEcId);
        if(key_data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(xmlSecGCryptKeyDataEcId)", NULL);
            goto done;
        }

        ret = xmlSecGCryptKeyDataEcAdoptKeyPair(key_data, s_pub_key, s_priv_key);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGCryptKeyDataEcAdoptKeyPair(xmlSecGCryptKeyDataEcId)", NULL);
            xmlSecKeyDataDestroy(key_data);
            key_data = NULL;
            goto done;
        }
        s_pub_key = NULL; /* owned by key_data now */
        s_priv_key = NULL; /* owned by key_data now */
        break;

    case xmlSecGCryptDerKeyTypePublicEc:
        /* check we have object id and enough integers */
        if(objectids_num < 1U) {
            xmlSecInvalidSizeError("Public EC requires object ID for curve",
                (xmlSecSize)objectids_num, (xmlSecSize)1U, NULL);
            goto done;
        }
        if(integers_num < XMLSEC_GNUTLS_ASN1_EDCSA_PUB_NUM) {
            xmlSecInvalidSizeError("Public EC key params",
                (xmlSecSize)integers_num, (xmlSecSize)XMLSEC_GNUTLS_ASN1_EDCSA_PUB_NUM, NULL);
            goto done;
        }

        /* search through all object ids to find the curve name */
        for(xmlSecSize ii = 0; (ii < objectids_num) && (ecCurve == NULL); ++ii) {
            ecCurve = xmlSecGCryptAsn1GetCurveFromObjectId(objectids[ii]);
        }
        if(ecCurve == NULL) {
            xmlSecInvalidDataError("Unknown EC curve Object ID", NULL);
            goto done;
        }

        /* Build the S-expression.  */
        /* the q parameter is always the last one */
        err = gcry_sexp_build (&s_pub_key, NULL,
            "(public-key"
            " (ecdsa"
            " (curve %s)"
            " (q %m)"
            " ))",
            ecCurve, integers[integers_num - 1]
        );
        if((err != GPG_ERR_NO_ERROR) || (s_pub_key == NULL)) {
            xmlSecGCryptError("gcry_sexp_build(public-key/ecdsa)", err, NULL);
            goto done;
        }

        /* construct key and key data */
        key_data = xmlSecKeyDataCreate(xmlSecGCryptKeyDataEcId);
        if(key_data == NULL) {
            xmlSecInternalError("xmlSecKeyDataCreate(xmlSecGCryptKeyDataEcId)", NULL);
            goto done;
        }

        ret = xmlSecGCryptKeyDataEcAdoptKeyPair(key_data, s_pub_key, NULL);
        if(ret < 0) {
            xmlSecInternalError("xmlSecGCryptKeyDataEcAdoptKeyPair(xmlSecGCryptKeyDataEcId)", NULL);
            xmlSecKeyDataDestroy(key_data);
            key_data = NULL;
            goto done;
        }
        s_pub_key = NULL; /* owned by key_data now */
        break;
#endif /* XMLSEC_NO_EC */

    default:
        xmlSecUnsupportedEnumValueError("key_type", type, NULL);
        goto done;
        break;
    }

done:
    if(s_priv_key != NULL) {
        gcry_sexp_release(s_priv_key);
    }
    if(s_pub_key != NULL) {
        gcry_sexp_release(s_pub_key);
    }
    for (idx = 0; idx < sizeof(integers) / sizeof(integers[0]); idx++) {
        if(integers[idx] != NULL) {
            gcry_mpi_release (integers[idx]);
        }
    }

    return(key_data);
}
