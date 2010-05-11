/**
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <string.h>

#include <gcrypt.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>

#include <xmlsec/gcrypt/crypto.h>

#include "src/gcrypt/asn1.h"

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
xmlSecGCryptAsn1ParseTag (xmlSecByte const **buffer, xmlSecSize *buflen, struct tag_info *ti)
{
    int c;
    unsigned long tag;
    const xmlSecByte *buf = *buffer;
    xmlSecSize length = *buflen;

    xmlSecAssert2(buffer != NULL, -1);
    xmlSecAssert2((*buffer) != NULL, -1);
    xmlSecAssert2(buflen != NULL, -1);
    xmlSecAssert2(ti != NULL, -1);

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
        xmlSecSize len = 0;
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

xmlSecKeyDataPtr
xmlSecGCryptParseDerPrivateKey(const xmlSecByte * der, xmlSecSize derlen) {
    xmlSecKeyDataPtr key_data = NULL;
    gcry_sexp_t s_key = NULL;
    gcry_error_t err;
    struct tag_info ti;
    gcry_mpi_t keyparms[8] = {
        NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL
    } ;
    int n_keyparms = sizeof(keyparms) / sizeof(keyparms[0]);
    int idx;
    int ret;

    xmlSecAssert2(der != NULL, NULL);
    xmlSecAssert2(derlen > 0, NULL);

    /* Parse the ASN.1 structure.  */
    if(xmlSecGCryptAsn1ParseTag (&der, &derlen, &ti)
       || ti.tag != TAG_SEQUENCE || ti.class || !ti.cons || ti.ndef)
    {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecGCryptAsn1ParseTag",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "TAG_SEQUENCE is expected");
        goto done;
    }

    if (xmlSecGCryptAsn1ParseTag (&der, &derlen, &ti)
       || ti.tag != TAG_INTEGER || ti.class || ti.cons || ti.ndef)
    {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecGCryptAsn1ParseTag",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "TAG_INTEGER is expected");
        goto done;
    }

    if ((ti.length != 1) || ((*der) != 0)) {
        /* The value of the first integer is no 0. */
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecGCryptAsn1ParseTag",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "integer length=%d, value=%d",
                    (int)ti.length, (int)(*der));
        goto done;
    }
    der += ti.length; 
    derlen -= ti.length;

    /* read params */
    for (idx=0; idx < n_keyparms; idx++) {
        if ( xmlSecGCryptAsn1ParseTag (&der, &derlen, &ti)
           || ti.tag != TAG_INTEGER || ti.class || ti.cons || ti.ndef)
        {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecGCryptAsn1ParseTag",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "TAG_INTEGER is expected - index=%d",
                        (int)idx);
            goto done;
        }

        err = gcry_mpi_scan (keyparms+idx, GCRYMPI_FMT_USG, der, ti.length,NULL);
        if (err) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "gcry_mpi_scan",
                        XMLSEC_ERRORS_R_CRYPTO_FAILED,
                        "err=%d", (int)err);
            goto done;
        }
        der += ti.length;
        derlen -= ti.length;
    }

    if (idx != n_keyparms) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecGCryptAsn1ParseTag",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "Not enough params: index=%d, expected=%d",
                    (int)idx, (int)n_keyparms);
        goto done;
    }

    /* Convert from OpenSSL parameter ordering to the OpenPGP order. */
    /* First check that p < q; if not swap p and q and recompute u.  */ 
    if (gcry_mpi_cmp (keyparms[3], keyparms[4]) > 0) {
        gcry_mpi_swap (keyparms[3], keyparms[4]);
        gcry_mpi_invm (keyparms[7], keyparms[3], keyparms[4]);
    }

    /* Build the S-expression.  */
    err = gcry_sexp_build (&s_key, NULL,
                         "(key-data"
                         "(public-key(rsa(n%m)(e%m)))"
                         "(private-key(rsa(n%m)(e%m)"
                         /**/            "(d%m)(p%m)(q%m)(u%m)))"
                         ")",
                         keyparms[0], keyparms[1],
                         keyparms[0], keyparms[1],
                         keyparms[2], keyparms[3], keyparms[4], keyparms[7]
    );
    if (err) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "gcry_sexp_build",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    "err=%d", (int)err);
        goto done;
    }

    key_data = xmlSecKeyDataCreate(xmlSecGCryptKeyDataRsaId);
    if(key_data == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecKeyDataCreate",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "xmlSecGCryptKeyDataRsaId");
        goto done;
    }

    ret = xmlSecGCryptKeyDataRsaAdoptKey(key_data, s_key);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    NULL,
                    "xmlSecGCryptKeyDataRsaAdoptKey",
                    XMLSEC_ERRORS_R_XMLSEC_FAILED,
                    "xmlSecGCryptKeyDataRsaId");
        xmlSecKeyDataDestroy(key_data);
        key_data = NULL;
        goto done;
    }
    s_key = NULL; /* owned by key_data now */

done:
    if(s_key != NULL) {
        gcry_sexp_release(s_key);
    }

    for (idx=0; idx < n_keyparms; idx++) {
        if(keyparms[idx] != NULL) {
            gcry_mpi_release (keyparms[idx]);
        }
    }

    return(key_data);
}


xmlSecKeyDataPtr
xmlSecGCryptParseDerPublicKey(const xmlSecByte * der, xmlSecSize derlen) {
    xmlSecAssert2(der != NULL, NULL);
    xmlSecAssert2(derlen > 0, NULL);

    /* aleksey todo */
    return(NULL);
}

#if 0
/* Read the file FNAME assuming it is a PEM encoded public key file
   and return an S-expression.  With SHOW set, the key parameters are
   printed.  */
static gcry_sexp_t
read_public_key_file (const char *fname, int show)
{
  gcry_error_t err;
  FILE *fp;
  char *buffer;
  size_t buflen;
  const unsigned char *der;
  size_t derlen;
  struct tag_info ti;
  gcry_mpi_t keyparms[2];
  int n_keyparms = 2;
  int idx;
  gcry_sexp_t s_key;

  fp = fopen (fname, binary_input?"rb":"r");
  if (!fp)
    die ("can't open `%s': %s\n", fname, strerror (errno));
  buffer = read_file (fp, 0, &buflen);
  if (!buffer)
    die ("error reading `%s'\n", fname);
  fclose (fp);

  buflen = base64_decode (buffer, buflen);
  
  /* Parse the ASN.1 structure.  */
  der = (const unsigned char*)buffer;
  derlen = buflen;
  if ( xmlSecGCryptAsn1ParseTag (&der, &derlen, &ti)
       || ti.tag != TAG_SEQUENCE || ti.class || !ti.cons || ti.ndef)
    goto bad_asn1;
  if ( xmlSecGCryptAsn1ParseTag (&der, &derlen, &ti)
       || ti.tag != TAG_SEQUENCE || ti.class || !ti.cons || ti.ndef)
    goto bad_asn1;
  /* We skip the description of the key parameters and assume it is RSA.  */
  der += ti.length; derlen -= ti.length;
  
  if ( xmlSecGCryptAsn1ParseTag (&der, &derlen, &ti)
       || ti.tag != TAG_BIT_STRING || ti.class || ti.cons || ti.ndef)
    goto bad_asn1;
  if (ti.length < 1 || *der)
    goto bad_asn1;  /* The number of unused bits needs to be 0. */
  der += 1; derlen -= 1;

  /* Parse the BIT string.  */
  if ( xmlSecGCryptAsn1ParseTag (&der, &derlen, &ti)
       || ti.tag != TAG_SEQUENCE || ti.class || !ti.cons || ti.ndef)
    goto bad_asn1;

  for (idx=0; idx < n_keyparms; idx++)
    {
      if ( xmlSecGCryptAsn1ParseTag (&der, &derlen, &ti)
           || ti.tag != TAG_INTEGER || ti.class || ti.cons || ti.ndef)
        goto bad_asn1;
      if (show)
        {
          char prefix[2];

          prefix[0] = idx < 2? "ne"[idx] : '?';
          prefix[1] = 0;
          showhex (prefix, der, ti.length);
        }
      err = gcry_mpi_scan (keyparms+idx, GCRYMPI_FMT_USG, der, ti.length,NULL);
      if (err)
        die ("error scanning RSA parameter %d: %s\n", idx, gpg_strerror (err));
      der += ti.length; derlen -= ti.length;
    }
  if (idx != n_keyparms)
    die ("not enough RSA key parameters\n");

  gcry_free (buffer);

  /* Build the S-expression.  */
  err = gcry_sexp_build (&s_key, NULL,
                         "(public-key(rsa(n%m)(e%m)))",
                         keyparms[0], keyparms[1] );
  if (err)
    die ("error building S-expression: %s\n", gpg_strerror (err));
  
  for (idx=0; idx < n_keyparms; idx++)
    gcry_mpi_release (keyparms[idx]);
  
  return s_key;
  
 bad_asn1:
  die ("invalid ASN.1 structure in `%s'\n", fname);
  return NULL; /*NOTREACHED*/
}
#endif /* 0 */


xmlSecKeyDataPtr
xmlSecGCryptParseDer(const xmlSecByte * der, xmlSecSize derlen) {
    xmlSecKeyDataPtr res = NULL;

    xmlSecAssert2(der != NULL, NULL);
    xmlSecAssert2(derlen > 0, NULL);

    /* try private key first */
    res = xmlSecGCryptParseDerPrivateKey(der, derlen);
    if(res == NULL) {
        res = xmlSecGCryptParseDerPublicKey(der, derlen);
    }

    return(res);
}

