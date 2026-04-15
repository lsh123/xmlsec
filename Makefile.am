#
# make all 			: builds everything
# make check    	: runs all tests
# make docs-build	: builds all docs (requires additional tools installed)
# make tar-release  : builds distribution tar.gz (including docs)
#
NULL =
SUBDIRS 	    = include src apps man docs

SAFE_VERSION	= @XMLSEC_VERSION_SAFE@

TEST_APP 	    = apps/xmlsec1$(EXEEXT)
UNIT_TEST_APP 	= apps/xmlsec_unit_tests$(EXEEXT)
DEFAULT_CRYPTO	= @XMLSEC_DEFAULT_CRYPTO@

bin_SCRIPTS 	= xmlsec1-config
pkgconfig_DATA 	= xmlsec1.pc @XMLSEC_CRYPTO_PC_FILES_LIST@
pkgconfigdir 	= $(libdir)/pkgconfig
confexecdir		= $(libdir)
confexec_DATA 	= xmlsec1Conf.sh
m4datadir		= $(datadir)/aclocal
m4data_DATA		= xmlsec1.m4

ACLOCAL_AMFLAGS	= -I m4

DISTCLEANFILES = \
	xmlsec1Conf.sh \
	xmlsec1.pc \
	xmlsec1-openssl.pc \
	xmlsec1-nss.pc \
	xmlsec1-gnutls.pc \
	xmlsec1-gcrypt.pc \
	xmlsec1-config \
	xmlsec1.spec \
	stamp-h2 \
	stamp-h3 \
	stamp-h4 \
	stamp-h5 \
	$NULL

EXTRA_DIST = \
	m4 \
	examples \
	scripts \
	tests \
	win32 \
	NEWS \
	ChangeLog \
	Copyright \
	HACKING \
	README.md \
	AUTHORS.md \
	xmlsec-openssl.pc.in \
	xmlsec-nss.pc.in\
	xmlsec-gnutls.pc.in \
	xmlsec-gcrypt.pc.in \
	xmlsec-config.in \
	xmlsecConf.sh.in \
	xmlsec.spec.in \
	xmlsec1Conf.sh \
	xmlsec1.pc @XMLSEC_CRYPTO_PC_FILES_LIST@ \
	xmlsec1-config \
	xmlsec1.spec \
	xmlsec1.m4 \
	$(NULL)

EXTRA_CLEAN = \
	examples \
	$(NULL)

ABS_SRCDIR=@abs_srcdir@
ABS_BUILDDIR=@abs_builddir@
XMLSEC_OPENSSL_TEST_CONFIG=@OPENSSL_TEST_CONFIG@
XMLSEC_OPENSSL_VERSION=@XMLSEC_OPENSSL_VERSION@

if XMLSEC_NO_APPS_CRYPTO_DYNAMIC_LOADING
PRECHECK_COMMANDS = \
	export XMLSEC_OPENSSL_TEST_CONFIG="$(XMLSEC_OPENSSL_TEST_CONFIG)" && \
	export XMLSEC_OPENSSL_VERSION="$(XMLSEC_OPENSSL_VERSION)" && \
	cd $(ABS_SRCDIR) \
	$(NULL)
else
PRECHECK_COMMANDS= \
	export XMLSEC_OPENSSL_TEST_CONFIG="$(XMLSEC_OPENSSL_TEST_CONFIG)" && \
	export XMLSEC_OPENSSL_VERSION="$(XMLSEC_OPENSSL_VERSION)" && \
	export LD_LIBRARY_PATH="$(ABS_BUILDDIR)/src/.libs:$$LD_LIBRARY_PATH" && \
	for i in $(XMLSEC_CHECK_CRYPTO_LIST) ; do \
		export LTDL_LIBRARY_PATH="$(ABS_BUILDDIR)/src/$$i/.libs:$$LTDL_LIBRARY_PATH" ; \
	done && \
	cd $(ABS_SRCDIR) \
	$(NULL)
endif

CHECK_CRYPTO_LIST = \
	$(XMLSEC_CHECK_CRYPTO_LIST) \
	$(NULL)


.PHONY: all check check-all check-info check-keys check-dsig check-enc docs-build

all:

check: check-all check-info

check-unit-tests: $(UNIT_TEST_APP)
	@($(PRECHECK_COMMANDS) && $(ABS_BUILDDIR)/$(UNIT_TEST_APP))

check-all: $(TEST_APP) check-unit-tests
	for crypto in $(CHECK_CRYPTO_LIST) ; do \
		make check-crypto-$$crypto || exit 1 ; \
	done

check-crypto-%: $(TEST_APP)
	@($(PRECHECK_COMMANDS) && \
	echo "=================== Checking xmlsec-$* =================================" && \
	$(SHELL) ./tests/testrun.sh \
		$(ABS_SRCDIR)/tests/testKeys.sh \
		$* \
		$(ABS_SRCDIR)/tests \
		$(ABS_BUILDDIR)/$(TEST_APP) der \
	&& \
	$(SHELL) ./tests/testrun.sh \
		$(ABS_SRCDIR)/tests/testDSig.sh \
		$* \
		$(ABS_SRCDIR)/tests \
		$(ABS_BUILDDIR)/$(TEST_APP) \
		der \
	&& \
	$(SHELL) ./tests/testrun.sh \
		$(ABS_SRCDIR)/tests/testEnc.sh \
		$* \
		$(ABS_SRCDIR)/tests \
		$(ABS_BUILDDIR)/$(TEST_APP) \
		der \
	; \
	)

check-info:
	@echo "---------------------------- ATTENTION -----------------------------------"
	@echo "--- Some tests use resources hosted on external HTTP servers.        ---"
	@echo "--- If you lack an Internet connection or an external resource is    ---"
	@echo "--- unavailable, the test will fail.                                ---"
	@echo "---------------------------- ATTENTION -----------------------------------"

check-keys: $(TEST_APP)
	@($(PRECHECK_COMMANDS) && \
	$(SHELL) ./tests/testrun.sh \
	    $(ABS_SRCDIR)/tests/testKeys.sh \
	    $(DEFAULT_CRYPTO) \
	    $(ABS_SRCDIR)/tests \
	    $(ABS_BUILDDIR)/$(TEST_APP) \
	    der \
	)

check-dsig: $(TEST_APP)
	@($(PRECHECK_COMMANDS) && \
	$(SHELL) ./tests/testrun.sh \
	    $(ABS_SRCDIR)/tests/testDSig.sh \
	    $(DEFAULT_CRYPTO) \
	    $(ABS_SRCDIR)/tests \
	    $(ABS_BUILDDIR)/$(TEST_APP) \
	    der \
	)

check-enc: $(TEST_APP)
	@($(PRECHECK_COMMANDS) && \
	$(SHELL) ./tests/testrun.sh \
	    $(ABS_SRCDIR)/tests/testEnc.sh  \
	    $(DEFAULT_CRYPTO) \
	    $(ABS_SRCDIR)/tests \
	    $(ABS_BUILDDIR)/$(TEST_APP) \
	    der \
	)

memcheck-res:
	@$(GREP) -i 'ERROR SUMMARY' /tmp/xmlsec-test*/*.log | $(SED) 's/.*==.*== *//' | $(SORT) -u
	@$(GREP) -i 'in use at exit' /tmp/xmlsec-test*/*.log | $(SED) 's/.*==.*== *//' | $(SORT) -u
	@$(GREP) -i 'definitely lost:' /tmp/xmlsec-test*/*.log | $(SED) 's/.*==.*== *//' | $(SORT) -u
	@$(GREP) -i 'indirectly lost:' /tmp/xmlsec-test*/*.log | $(SED) 's/.*==.*== *//' | $(SORT) -u
	@$(GREP) -i 'possibly lost:' /tmp/xmlsec-test*/*.log | $(SED) 's/.*==.*== *//' | $(SORT) -u
	@$(GREP) -i 'still reachable:' /tmp/xmlsec-test*/*.log | $(SED) 's/.*==.*== *//' | $(SORT) -u
	@$(GREP) -i 'used_suppression:' /tmp/xmlsec-test*/*.log | $(SED) 's/.*--.*-- *//' | $(SORT) -u

memcheck: $(TEST_APP)
	@(export DEBUG_MEMORY=1 && $(MAKE) $(AM_MAKEFLAGS) check && $(MAKE) $(AM_MAKEFLAGS) memcheck-res)

memcheck-crypto-%: $(TEST_APP)
	@(export DEBUG_MEMORY=1 && $(MAKE) $(AM_MAKEFLAGS) check-crypto-$* && $(MAKE) $(AM_MAKEFLAGS) memcheck-res)

perfcheck: $(TEST_APP)
	@(export PERF_TEST=10 && $(MAKE) $(AM_MAKEFLAGS) check)

# build docs before running make dist
tar-release: docs-build
	@(unset CDPATH && $(MAKE) $(AM_MAKEFLAGS) dist)

cleantar:
	@($(RM) -f xmlsec*.tar.gz COPYING.LIB)


docs-build: all
	@$(MAKE) $(AM_MAKEFLAGS) -C man docs
	@$(MAKE) $(AM_MAKEFLAGS) -C docs docs
