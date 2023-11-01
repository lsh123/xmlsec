NULL =
examples_dir = $(top_srcdir)/examples

bin_PROGRAMS = sign1 sign2 sign3 \
	verify1 verify2 verify3 verify4 \
	encrypt1 encrypt2 encrypt3 \
	decrypt1 decrypt2 decrypt3 \
	xmldsigverify

sign1_SOURCES = sign1.c
sign2_SOURCES = sign2.c
sign3_SOURCES = sign3.c
verify1_SOURCES = verify1.c
verify2_SOURCES = verify2.c
verify3_SOURCES = verify3.c
verify4_SOURCES = verify4.c
encrypt1_SOURCES = encrypt1.c
encrypt2_SOURCES = encrypt2.c
encrypt3_SOURCES = encrypt3.c
decrypt1_SOURCES = decrypt1.c
decrypt2_SOURCES = decrypt2.c
decrypt3_SOURCES = decrypt3.c
xmldsigverify_SOURCES = xmldsigverify.c

CLEANFILES = \
	*.xml \
	$(NULL)

# link all examples statically to make life simpler
XMLSEC_LIBS = \
	$(top_builddir)/src/libxmlsec1.la \
	$(top_builddir)/src/@XMLSEC_DEFAULT_CRYPTO@/lib$(XMLSEC_CRYPTO_LIB).la \
	$(NULL)

AM_CFLAGS = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I../include \
	-I$(top_srcdir)/include \
	$(XMLSEC_DEFINES) \
	@XMLSEC_EXTRA_APP_CFLAGS@ \
	$(XMLSEC_CRYPTO_CFLAGS) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(LIBLTDL_CFLAGS) \
	$(NULL)

 LDFLAGS = \
	@XMLSEC_STATIC_BINARIES@ \
	@XMLSEC_EXTRA_LDFLAGS@ \
	@XMLSEC_EXTRA_APP_LDFLAGS@ \
	$(NULL)

LDADD = \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	$(XMLSEC_LIBS) \
	$(LIBLTDL_LIBS) \
	$(NULL)

DEPENDENCIES = \
	$(CRYPTO_DEPS) \
	$(XMLSEC_LIBS) \
	$(NULL)


check:
	./sign1     $(examples_dir)/sign1-tmpl.xml    $(examples_dir)/rsakey.pem  > sign1-out.xml
	./sign2     $(examples_dir)/sign2-doc.xml     $(examples_dir)/rsakey.pem  > sign2-out.xml
	./sign3     $(examples_dir)/sign3-doc.xml     $(examples_dir)/rsakey.pem $(examples_dir)/rsacert.pem > sign3-out.xml
	./verify1   $(examples_dir)/sign1-res.xml     $(examples_dir)/rsapub.pem
	./verify1   $(examples_dir)/sign2-res.xml     $(examples_dir)/rsapub.pem
	./verify1   sign1-out.xml                     $(examples_dir)/rsapub.pem
	./verify1   sign2-out.xml                     $(examples_dir)/rsapub.pem
	./verify2   $(examples_dir)/sign1-res.xml     $(examples_dir)/rsakey.pem
	./verify2   $(examples_dir)/sign2-res.xml     $(examples_dir)/rsakey.pem
	./verify2   sign1-out.xml                     $(examples_dir)/rsakey.pem
	./verify2   sign2-out.xml                     $(examples_dir)/rsakey.pem
	./verify3   $(examples_dir)/sign3-res.xml     $(examples_dir)/ca2cert.pem $(examples_dir)/cacert.pem
	./verify3   sign3-out.xml                     $(examples_dir)/ca2cert.pem $(examples_dir)/cacert.pem
	./verify4   $(examples_dir)/verify4-res.xml   $(examples_dir)/ca2cert.pem $(examples_dir)/cacert.pem
	./encrypt1  $(examples_dir)/encrypt1-tmpl.xml $(examples_dir)/deskey.bin  > encrypt1-out.xml
	./encrypt2  $(examples_dir)/encrypt2-doc.xml  $(examples_dir)/deskey.bin  > encrypt2-out.xml
	./encrypt3  $(examples_dir)/encrypt3-doc.xml  $(examples_dir)/rsakey.pem  > encrypt3-out.xml
	./decrypt1  $(examples_dir)/encrypt1-res.xml  $(examples_dir)/deskey.bin  > decrypt1-1-out.xml
	./decrypt1  $(examples_dir)/encrypt2-res.xml  $(examples_dir)/deskey.bin  > decrypt1-2-out.xml
	./decrypt1  encrypt1-out.xml                  $(examples_dir)/deskey.bin  > decrypt1-3-out.xml
	./decrypt1  encrypt2-out.xml                  $(examples_dir)/deskey.bin  > decrypt1-4-out.xml
	./decrypt2  $(examples_dir)/encrypt1-res.xml  $(examples_dir)/deskey.bin  > decrypt2-1-out.xml
	./decrypt2  $(examples_dir)/encrypt2-res.xml  $(examples_dir)/deskey.bin  > decrypt2-2-out.xml
	./decrypt2  encrypt1-out.xml                  $(examples_dir)/deskey.bin  > decrypt2-3-out.xml
	./decrypt2  encrypt2-out.xml                  $(examples_dir)/deskey.bin  > decrypt2-4-out.xml
	./decrypt3  $(examples_dir)/encrypt1-res.xml  $(examples_dir)             > decrypt3-1-out.xml
	./decrypt3  $(examples_dir)/encrypt2-res.xml  $(examples_dir)             > decrypt3-2-out.xml
	./decrypt3  $(examples_dir)/encrypt3-res.xml  $(examples_dir)             > decrypt3-3-out.xml
	./decrypt3  encrypt1-out.xml                  $(examples_dir)             > decrypt3-4-out.xml
	./decrypt3  encrypt2-out.xml                  $(examples_dir)             > decrypt3-5-out.xml
	./decrypt3  encrypt3-out.xml                  $(examples_dir)             > decrypt3-6-out.xml
