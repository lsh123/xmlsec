/**
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see the Copyright file in the source distribution for precise wording.
 *
 * Copyright (C) 2002-2026 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#ifndef XMLSEC_EXPORTS_H
#define XMLSEC_EXPORTS_H
/**
 * @brief Platform-specific symbol visibility and export macros.
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* There are many variations of Windows */
#if !defined(XMLSEC_WINDOWS)

#if defined(WIN32) || defined(_WIN32) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__MINGW64__)
#define XMLSEC_WINDOWS 1
#endif /* defined(WIN32) || defined(_WIN32) */

#endif /* !defined(XMLSEC_WINDOWS) */

/**
 * Now, the export fun begins. The following must be done for the Windows platform.
 */

 /* XMLSEC_EXPORT macro should only be used in the "core" library */
#if !defined XMLSEC_EXPORT
#  if defined(XMLSEC_WINDOWS)
     /* if we compile libxmlsec itself: */
#    if defined(IN_XMLSEC)
#      if !defined(XMLSEC_STATIC)
#        define XMLSEC_EXPORT __declspec(dllexport)
#      else
#        define XMLSEC_EXPORT extern
#      endif
     /* if a client program includes this file: */
#    else
#      if !defined(XMLSEC_STATIC)
#        define XMLSEC_EXPORT __declspec(dllimport)
#      else
#        define XMLSEC_EXPORT extern
#      endif
#    endif /* defined(IN_XMLSEC) */
   /* This holds on all other platforms/compilers, which are easier to
      handle in regard to this. */
#  else /* defined(XMLSEC_WINDOWS) */
#    if defined(__GNUC__) || defined(__clang__)
#      define XMLSEC_EXPORT __attribute__((visibility("default")))
#    else
#      define XMLSEC_EXPORT
#    endif
#  endif /* defined(XMLSEC_WINDOWS) */
#endif /* !defined XMLSEC_EXPORT */

 /* XMLSEC_CRYPTO_EXPORT macro should only be used in the xmlsec-<crypto> libraries */
#if !defined XMLSEC_CRYPTO_EXPORT
#  if defined(XMLSEC_WINDOWS)
     /* if we compile libxmlsec-<crypto> itself: */
#    if defined(IN_XMLSEC_CRYPTO)
#      if !defined(XMLSEC_STATIC)
#        define XMLSEC_CRYPTO_EXPORT __declspec(dllexport)
#      else
#        define XMLSEC_CRYPTO_EXPORT extern
#      endif
     /* if a client program includes this file: */
#    else /* defined(IN_XMLSEC_CRYPTO) */
#      if !defined(XMLSEC_STATIC)
#        define XMLSEC_CRYPTO_EXPORT __declspec(dllimport)
#      else
#        define XMLSEC_CRYPTO_EXPORT extern
#      endif
#    endif /* defined(IN_XMLSEC_CRYPTO) */
   /* This holds on all other platforms/compilers, which are easier to
      handle in regard to this. */
#  else  /* defined(XMLSEC_WINDOWS) */
#    if defined(__GNUC__) || defined(__clang__)
#      define XMLSEC_CRYPTO_EXPORT __attribute__((visibility("default")))
#    else
#      define XMLSEC_CRYPTO_EXPORT
#    endif
#  endif  /* defined(XMLSEC_WINDOWS) */
#endif /* !defined XMLSEC_CRYPTO_EXPORT */


 /* XMLSEC_EXPORT_VAR macro should only be used in the "core" and xmlsec-<crypto> libraries */
#if !defined XMLSEC_EXPORT_VAR
#  if defined(XMLSEC_WINDOWS)
     /* if we compile libxmlsec itself: */
#    if defined(IN_XMLSEC)
#      if !defined(XMLSEC_STATIC)
#        define XMLSEC_EXPORT_VAR __declspec(dllexport) extern
#      else
#        define XMLSEC_EXPORT_VAR extern
#      endif
     /* if we compile libxmlsec-crypto itself: */
#    elif defined(IN_XMLSEC_CRYPTO)
#      if !defined(XMLSEC_STATIC)
#        define XMLSEC_EXPORT_VAR __declspec(dllexport) extern
#      else
#        define XMLSEC_EXPORT_VAR extern
#      endif
     /* if a client program includes this file: */
#    else
#      if !defined(XMLSEC_STATIC)
#        define XMLSEC_EXPORT_VAR __declspec(dllimport) extern
#      else
#        define XMLSEC_EXPORT_VAR extern
#      endif
#    endif
   /* This holds on all other platforms/compilers, which are easier to
      handle in regard to this. */
#  else /* defined(XMLSEC_WINDOWS) */
#    if defined(__GNUC__) || defined(__clang__)
#      define XMLSEC_EXPORT_VAR __attribute__((visibility("default"))) extern
#    else
#      define XMLSEC_EXPORT_VAR extern
#    endif
#  endif  /* defined(XMLSEC_WINDOWS) */
#endif /* !defined XMLSEC_EXPORT_VAR */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XMLSEC_EXPORTS_H */
