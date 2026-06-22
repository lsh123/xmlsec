NULL =

bin_PROGRAMS = xmlsec1
noinst_PROGRAMS = xmlsec_unit_tests xmlsec_fuzzer

XMLSEC_LIBS = $(top_builddir)/src/libxmlsec1.la


# check if we use dynamic loading for xmlsec-crypto or not
if XMLSEC_NO_APPS_CRYPTO_DYNAMIC_LOADING

CRYPTO_DEPS = \
	$(top_builddir)/src/@XMLSEC_DEFAULT_CRYPTO@/lib$(XMLSEC_CRYPTO_LIB).la \
	$(NULL)

CRYPTO_INCLUDES = \
	$(XMLSEC_CRYPTO_CFLAGS) \
	$(NULL)

CRYPTO_LD_FLAGS = \
	$(NULL)

CRYPTO_LD_ADD = \
	$(XMLSEC_CRYPTO_LIBS) \
	$(CRYPTO_DEPS) \
	$(NULL)

else

CRYPTO_DEPS =  \
	$(NULL)

CRYPTO_INCLUDES = \
	-DXMLSEC_CRYPTO_DYNAMIC_LOADING=1
	$(NULL)

CRYPTO_LD_FLAGS = \
	$(NULL)

CRYPTO_LD_ADD = \
	$(CRYPTO_DEPS) \
	$(NULL)

endif

AM_CFLAGS = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I../include \
	-I$(top_srcdir)/include \
	$(XMLSEC_DEFINES) \
	$(XMLSEC_APP_DEFINES) \
	$(CRYPTO_INCLUDES) \
	$(LIBXSLT_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(LIBLTDL_CFLAGS) \
	$(NULL)

# xmlsec command line utility
xmlsec1_SOURCES = \
	xmlsec.c \
	crypto.c crypto.h \
	cmdline.c cmdline.h \
	$(NULL)


xmlsec1_LDFLAGS = \
	@XMLSEC_STATIC_BINARIES@ \
	@XMLSEC_EXTRA_LDFLAGS@ \
	$(CRYPTO_LD_FLAGS) \
	$(NULL)

xmlsec1_LDADD = \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	$(CRYPTO_LD_ADD) \
	$(XMLSEC_LIBS) \
	$(LIBLTDL_LIBS) \
	$(NULL)

xmlsec1_DEPENDENCIES = \
	$(CRYPTO_DEPS) \
	$(XMLSEC_LIBS) \
	$(NULL)

# xmlsec unit tests
xmlsec_unit_tests_SOURCES = \
	unit_tests/base64_unit_tests.c \
	unit_tests/bn_unit_tests.c \
	unit_tests/buffer_unit_tests.c \
	unit_tests/list_unit_tests.c \
	unit_tests/nodeset_unit_tests.c \
	unit_tests/transform_helpers_unit_tests.c \
	unit_tests/x509_unit_tests.c \
	unit_tests/xmltree_unit_tests.c \
	unit_tests/templates_unit_tests.c \
	unit_tests/xmlsec_unit_tests.h \
	unit_tests/xmlsec_unit_tests.c \
	$(NULL)


xmlsec_unit_tests_LDFLAGS = \
	@XMLSEC_STATIC_BINARIES@ \
	@XMLSEC_EXTRA_LDFLAGS@ \
	$(CRYPTO_LD_FLAGS) \
	$(NULL)

xmlsec_unit_tests_LDADD = \
	$(LIBXSLT_LIBS) \
	$(LIBXML_LIBS) \
	$(CRYPTO_LD_ADD) \
	$(XMLSEC_LIBS) \
	$(LIBLTDL_LIBS) \
	$(NULL)

xmlsec_unit_tests_DEPENDENCIES = \
	$(CRYPTO_DEPS) \
	$(XMLSEC_LIBS) \
	$(NULL)

# xmlsec fuzzer (OSS-Fuzz harness — XML parsing surface, no crypto dependency)
xmlsec_fuzzer_SOURCES = \
	oss-fuzz/xmlsec_target.c \
	oss-fuzz/standalone_fuzz_runner.c \
	$(NULL)

xmlsec_fuzzer_CFLAGS = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I../include \
	-I$(top_srcdir)/include \
	$(XMLSEC_DEFINES) \
	$(LIBXML_CFLAGS) \
	$(NULL)

xmlsec_fuzzer_LDFLAGS = \
	@XMLSEC_STATIC_BINARIES@ \
	@XMLSEC_EXTRA_LDFLAGS@ \
	$(NULL)

xmlsec_fuzzer_LDADD = \
	$(LIBXML_LIBS) \
	$(XMLSEC_LIBS) \
	$(NULL)

xmlsec_fuzzer_DEPENDENCIES = \
	$(XMLSEC_LIBS) \
	$(NULL)

# xmlsec DSig-verify fuzzer (OSS-Fuzz harness — OpenSSL only)
if !XMLSEC_NO_OPENSSL
noinst_PROGRAMS += xmlsec_dsig_verify_fuzzer

XMLSEC_OPENSSL_LIB = $(top_builddir)/src/openssl/libxmlsec1-openssl.la

xmlsec_dsig_verify_fuzzer_SOURCES = \
	oss-fuzz/xmlsec_dsig_verify_target.c \
	oss-fuzz/standalone_fuzz_runner.c \
	$(NULL)

xmlsec_dsig_verify_fuzzer_CFLAGS = \
	-DPACKAGE=\"@PACKAGE@\" \
	-I../include \
	-I$(top_srcdir)/include \
	$(XMLSEC_DEFINES) \
	$(XMLSEC_OPENSSL_CFLAGS) \
	$(LIBXML_CFLAGS) \
	$(NULL)

xmlsec_dsig_verify_fuzzer_LDFLAGS = \
	@XMLSEC_STATIC_BINARIES@ \
	@XMLSEC_EXTRA_LDFLAGS@ \
	$(NULL)

xmlsec_dsig_verify_fuzzer_LDADD = \
	$(LIBXML_LIBS) \
	$(OPENSSL_LIBS) \
	$(XMLSEC_OPENSSL_LIB) \
	$(XMLSEC_LIBS) \
	$(NULL)

xmlsec_dsig_verify_fuzzer_DEPENDENCIES = \
	$(XMLSEC_OPENSSL_LIB) \
	$(XMLSEC_LIBS) \
	$(NULL)

endif # !XMLSEC_NO_OPENSSL
