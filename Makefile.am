NULL =

SAFE_VERSION	= @XMLSEC_VERSION_SAFE@
SUBDIRS 	= include src apps man docs
TEST_APP 	= apps/xmlsec1

bin_SCRIPTS 	= xmlsec1-config
pkgconfig_DATA 	= xmlsec1.pc
pkgconfigdir 	= $(libdir)/pkgconfig
confexecdir	= $(libdir)
confexec_DATA 	= xmlsec1Conf.sh

DISTCLEANFILES = \
	xmlsec1Conf.sh \
	xmlsec1.pc \
	xmlsec1-config \
	xmlsec1.spec \
	$NULL

EXTRA_DIST = \
	examples \
	scripts \
	tests \
	win32 \
	NEWS \
	ChangeLog \
	Copyright \
	xmlsec.pc.in \
	xmlsec-config.in \
	xmlsecConf.sh.in \
	xmlsec.spec.in \
	xmlsec1Conf.sh \
	xmlsec1.pc \
	xmlsec1-config \
	xmlsec1.spec \
	$(NULL)

EXTRA_CLEAN = \
	examples \
	$(NULL)

docs: docs-man
	@(cd docs; $(MAKE) docs)

docs-clean: 
	@(cd docs; $(MAKE) clean)

docs-man: 
	@(cd man;$(MAKE) docs)

check: check-info check-km check-dsig check-enc

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
	@(cd $(top_srcdir);\
	$(SHELL) ./tests/testKeys.sh ./tests $(top_builddir)/$(TEST_APP) der)

check-dsig: $(TEST_APP)
	@(cd $(top_srcdir);\
	$(SHELL) ./tests/testDSig.sh ./tests $(top_builddir)/$(TEST_APP) der pkcs8)

check-enc: $(TEST_APP)
	@(cd $(top_srcdir);\
	$(SHELL) ./tests/testEnc.sh ./tests $(top_builddir)/$(TEST_APP) der pkcs8)

memcheck-res:
	@grep -i lost /tmp/*.log | sed 's/==.*== *//' | sort -u
	@grep -i leak /tmp/*.log | sed 's/==.*== *//' | sort -u

memcheck: $(TEST_APP)
	@(export DEBUG_MEMORY=1;$(MAKE) check;$(MAKE) memcheck-res)

perfcheck: $(TEST_APP)
	@(export PERF_TEST=10;$(MAKE) check)

dist-hook:
	@(rm -rf `find $(distdir) -name CVS`)

cleantar:
	@(rm -f xmlsec*.tar.gz COPYING.LIB)

rpm: cleantar
	@(unset CDPATH ; $(MAKE) dist && rpmbuild -ta $(distdir).tar.gz)

tag-release:
	@cvs tag -F xmlsec-$(SAFE_VERSION) > /dev/null

rpm-release: clean cleantar rpm tag-release
	

