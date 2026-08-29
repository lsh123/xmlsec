# Makefile for building the xmlsec example programs against an installed xmlsec.
#
# Usage:
#   make            - build all example programs
#   make check      - run the sign/verify and encrypt/decrypt checks
#   make clean      - remove the built programs and object files
#

PROGRAMS_SIGN   = sign1 sign2 sign3 sign4
PROGRAMS_VERIFY = verify1 verify2 verify3 verify4 verify-saml
PROGRAMS_ENC    = encrypt1 encrypt2 encrypt3
PROGRAMS_DEC    = decrypt1 decrypt2 decrypt3
PROGRAMS = \
	$(PROGRAMS_SIGN) \
	$(PROGRAMS_VERIFY) \
	$(PROGRAMS_ENC) \
	$(PROGRAMS_DEC)

# try to find pkg-config, if available
XMLSEC_PKG_CONFIG = xmlsec1
PKG_CONFIG := $(shell command -v pkg-config 2> /dev/null)
XMLSEC_CHECK := $(shell $(PKG_CONFIG) --exists $(XMLSEC_PKG_CONFIG) 2> /dev/null && echo "found")

# retrieve flags if installed
ifeq ($(XMLSEC_CHECK),found)
	override CFLAGS += $(shell $(PKG_CONFIG) --cflags $(XMLSEC_PKG_CONFIG))
	override LDLIBS += $(shell $(PKG_CONFIG) --libs $(XMLSEC_PKG_CONFIG))
else
	XMLSEC1_CONFIG := $(shell command -v xmlsec1-config 2> /dev/null)
	ifeq ($(XMLSEC1_CONFIG),)
		$(error xmlsec is not installed: neither the pkg-config module 'xmlsec1' nor 'xmlsec1-config' was found)
	endif
	override CFLAGS += $(shell xmlsec1-config --cflags)
	override LDLIBS += $(shell xmlsec1-config --libs)
endif

# add compiler specific flags
CC_VERSION := $(shell $(CC) -v 2>&1)
ifeq ($(CC_VERSION),)
	CC_VERSION := $(shell $(CC) --version 2>&1)
endif
CC_VERSION_LC := $(shell printf '%s' "$(CC_VERSION)" | tr '[:upper:]' '[:lower:]')
ifneq (,$(findstring gcc, $(CC_VERSION_LC)))
	override CFLAGS += -g -Wall -Wextra
endif
ifneq (,$(findstring clang, $(CC_VERSION_LC)))
	override CFLAGS += -g -Wall -Wextra
endif

# rules
.PHONY: all clean check check-sign check-verify check-enc check-dec

all: $(PROGRAMS)

clean:
	rm -rf $(PROGRAMS) *.o

check: check-sign check-verify check-enc check-dec

check-sign: $(PROGRAMS_SIGN)
	./sign1    sign1-tmpl.xml    rsakey.pem
	./sign2    sign2-doc.xml     rsakey.pem
	./sign3    sign3-doc.xml     rsakey.pem rsacert.pem
	./sign4    sign4-doc.xml "data" rsakey.pem rsacert.pem

check-verify: check-sign $(PROGRAMS_VERIFY)
	./verify1  sign1-res.xml     rsapub.pem
	./verify1  sign2-res.xml     rsapub.pem
	./verify2  sign1-res.xml     rsakey.pem
	./verify2  sign2-res.xml     rsakey.pem
	./verify3  sign3-res.xml     ca2cert.pem cacert.pem
	./verify4  sign4-res.xml "data" ca2cert.pem cacert.pem
	./verify-saml verify-saml-res.xml ca2cert.pem cacert.pem

check-enc: $(PROGRAMS_ENC)
	./encrypt1 encrypt1-tmpl.xml deskey.bin
	./encrypt2 encrypt2-doc.xml  deskey.bin
	./encrypt3 encrypt3-doc.xml  rsakey.pem

check-dec: check-enc $(PROGRAMS_DEC)
	./decrypt1 encrypt1-res.xml  deskey.bin
	./decrypt1 encrypt2-res.xml  deskey.bin
	./decrypt2 encrypt1-res.xml  deskey.bin
	./decrypt2 encrypt2-res.xml  deskey.bin
	./decrypt3 encrypt1-res.xml
	./decrypt3 encrypt2-res.xml
	./decrypt3 encrypt3-res.xml
