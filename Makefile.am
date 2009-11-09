NULL =

SAFE_VERSION	= @XMLSEC_VERSION_SAFE@
SUBDIRS 	= include src apps man docs
TEST_APP 	= apps/xmlsec1$(EXEEXT)
DEFAULT_CRYPTO	= @XMLSEC_CRYPTO@

bin_SCRIPTS 	= xmlsec1-config
pkgconfig_DATA 	= xmlsec1.pc @XMLSEC_CRYPTO_PC_FILES_LIST@
pkgconfigdir 	= $(libdir)/pkgconfig
confexecdir	= $(libdir)
confexec_DATA 	= xmlsec1Conf.sh
m4datadir	= $(datadir)/aclocal
m4data_DATA	= xmlsec1.m4

ACLOCAL_AMFLAGS	= -I m4

DISTCLEANFILES = \
	xmlsec1Conf.sh \
	xmlsec1.pc xmlsec1-openssl.pc xmlsec1-gnutls.pc xmlsec1-nss.pc \
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
	xmlsec-openssl.pc.in xmlsec-gnutls.pc.in xmlsec-nss.pc.in\
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
if XMLSEC_NO_APPS_CRYPTO_DYNAMIC_LOADING
PRECHECK_COMMANDS = \
	cd $(ABS_SRCDIR) \
	$(NULL)
CHECK_CRYPTO_LIST = \
	"default" \
	$(NULL)
else
PRECHECK_COMMANDS= \
	for i in $(XMLSEC_CRYPTO_LIST) ; do \
	    export LD_LIBRARY_PATH="$(ABS_BUILDDIR)/src/$$i/.libs:$$LD_LIBRARY_PATH" ; \
	done && \
	cd $(ABS_SRCDIR) \
	$(NULL)	
CHECK_CRYPTO_LIST = \
	$(XMLSEC_CRYPTO_LIST) \
	$(NULL)
endif

docs: docs-man
	@(cd docs && $(MAKE) docs)

docs-clean: 
	@(cd docs && $(MAKE) clean)

docs-man: 
	@(cd man && $(MAKE) docs)

check: check-all check-info 

check-all: $(TEST_APP) 
	@($(PRECHECK_COMMANDS) && \
	for i in $(CHECK_CRYPTO_LIST) ; do \
	    echo "=================== Checking xmlsec-$$i =================================" && \
	    $(SHELL) ./tests/testKeys.sh $$i $(ABS_SRCDIR)/tests $(ABS_BUILDDIR)/$(TEST_APP) der && \
	    $(SHELL) ./tests/testDSig.sh $$i $(ABS_SRCDIR)/tests $(ABS_BUILDDIR)/$(TEST_APP) der && \
	    $(SHELL) ./tests/testEnc.sh  $$i $(ABS_SRCDIR)/tests $(ABS_BUILDDIR)/$(TEST_APP) der ; \
	done; )

check-info:
	@echo "-------------------------- ATTENTION -----------------------------------"
	@echo "--- 1) Some of the following tests use resources located on external ---"
	@echo "--- HTTP servers. If you have no Internet connection or the external ---"
	@echo "--- resource is not responding then the test will fail.              ---"
	@echo "--- 2) The test fails if corresponding feature(s) is disabled.       ---"
	@echo "--- Please, don't be surprised that many XML Encryption tests fails  ---"
	@echo "--- when you use OpenSSL 0.9.6 (see the FAQ for details)             ---"
	@echo "-------------------------- ATTENTION -----------------------------------"

check-km: $(TEST_APP)
	@($(PRECHECK_COMMANDS) && \
	$(SHELL) ./tests/testKeys.sh default $(ABS_SRCDIR)/tests $(ABS_BUILDDIR)/$(TEST_APP) der)

check-dsig: $(TEST_APP) 	
	@($(PRECHECK_COMMANDS) && \
	$(SHELL) ./tests/testDSig.sh default $(ABS_SRCDIR)/tests $(ABS_BUILDDIR)/$(TEST_APP) der)

check-xkms: $(TEST_APP) 	
	@($(PRECHECK_COMMANDS) && \
	$(SHELL) ./tests/testXKMS.sh default $(ABS_SRCDIR)/tests $(ABS_BUILDDIR)/$(TEST_APP) der)

check-enc: $(TEST_APP) 
	@($(PRECHECK_COMMANDS) && \
	$(SHELL) ./tests/testEnc.sh  default $(ABS_SRCDIR)/tests $(ABS_BUILDDIR)/$(TEST_APP) der)

memcheck-res:
	@grep -i lost /tmp/*.log | sed 's/==.*== *//' | sort -u
	@grep -i leak /tmp/*.log | sed 's/==.*== *//' | sort -u
	@grep -i 'in use' /tmp/*.log | sed 's/==.*== *//' | sort -u

memcheck: $(TEST_APP)
	@(export DEBUG_MEMORY=1 && $(MAKE) check && $(MAKE) memcheck-res)

perfcheck: $(TEST_APP)
	@(export PERF_TEST=10 && $(MAKE) check)

dist-hook:

cleantar:
	@($(RM) -f xmlsec*.tar.gz COPYING.LIB)

rpm: cleantar
	@(unset CDPATH && $(MAKE) dist && rpmbuild -ta $(distdir).tar.gz)

rpm-release: clean cleantar rpm 
	

