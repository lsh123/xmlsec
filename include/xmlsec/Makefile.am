NULL=
SUBDIRS = $(XMLSEC_CRYPTO)

xmlsecincdir = $(includedir)/xmlsec

xmlsecinc_HEADERS = \
base64.h \
buffered.h \
ciphers.h \
crypto.h \
debug.h \
digests.h \
errors.h \
io.h \
keyinfo.h \
keys.h \
keyvalue.h \
keysInternal.h \
keysmngr.h \
list.h \
map.h \
membuf.h \
nodeset.h \
object.h \
pgp.h \
serializable.h \
strings.h \
transforms.h \
transformsInternal.h \
version.h \
x509.h \
xmldsig.h \
xmlenc.h \
xmlsec.h \
xmltree.h \
$(NULL)

install-exec-hook:
	$(mkinstalldirs) $(DESTDIR)$(xmlsecincdir)

