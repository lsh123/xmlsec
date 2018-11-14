LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

# boringssl starts from android 6.0, sdk version > 22
ifeq ($(strip $(PLATFORM_SDK_VERSION)), 19)
XMLSEC_CRYPTO_BORINGSSL := false
else ifeq ($(strip $(PLATFORM_SDK_VERSION)), 20)
XMLSEC_CRYPTO_BORINGSSL := false
else ifeq ($(strip $(PLATFORM_SDK_VERSION)), 21)
XMLSEC_CRYPTO_BORINGSSL := false
else ifeq ($(strip $(PLATFORM_SDK_VERSION)), 22)
XMLSEC_CRYPTO_BORINGSSL := false
else
XMLSEC_CRYPTO_BORINGSSL := true
endif


LOCAL_SRC_FILES := \
    src/openssl/crypto.c \
    src/openssl/signatures.c \
    src/openssl/app.c \
    src/openssl/digests.c \
    src/openssl/symkeys.c \
    src/openssl/evp_signatures.c \
    src/openssl/hmac.c \
    src/openssl/evp.c \
    src/openssl/x509.c \
    src/openssl/x509vfy.c \
    src/openssl/bn.c \
    src/openssl/ciphers.c \
    src/openssl/kw_des.c \
    src/openssl/kw_aes.c \
    src/openssl/kt_rsa.c \
    src/kw_aes_des.c \
    src/keysdata.c \
    src/keysmngr.c \
    src/templates.c \
    src/bn.c \
    src/xmlenc.c \
    src/io.c \
    src/membuf.c \
    src/enveloped.c \
    src/dl.c \
    src/relationship.c \
    src/app.c \
    src/xmldsig.c \
    src/x509.c \
    src/strings.c \
    src/buffer.c \
    src/xmlsec.c \
    src/nodeset.c \
    src/xmltree.c \
    src/c14n.c \
    src/errors.c \
    src/list.c \
    src/keys.c \
    src/xpath.c \
    src/xslt.c \
    src/keyinfo.c \
    src/base64.c \
    src/parser.c \
    src/transforms.c \
    apps/cmdline.c \
    apps/crypto.c \
    apps/xmlsec.c \

LOCAL_C_INCLUDES += \
    $(LOCAL_PATH)/include \
    external/libxml2/include \
    external/icu/icu4c/source/common \


ifeq ($(strip $(XMLSEC_CRYPTO_BORINGSSL)), true)
LOCAL_C_INCLUDES += external/boringssl/include
LOCAL_CFLAGS += -DXMLSEC_NO_DSA # TODO
else
LOCAL_C_INCLUDES += external/openssl/include
endif


LOCAL_STATIC_LIBRARIES := libxml2
LOCAL_SHARED_LIBRARIES := libssl
LOCAL_CFLAGS += \
    -DXMLSEC_NO_XSLT \
    -DXMLSEC_NO_RIPEMD160 \
    -DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING \
    -DXMLSEC_DEFAULT_CRYPTO=\"openssl\" \
    -DXMLSEC_CRYPTO_OPENSSL \
    -DPACKAGE=\"xmlsec1\" \
    -Wall

LOCAL_CFLAGS += -fvisibility=hidden
LOCAL_MODULE    := libxmlsec1

include $(BUILD_STATIC_LIBRARY)
