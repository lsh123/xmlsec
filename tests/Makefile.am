NULL =

XMLSEC_APP = $(top_builddir)/apps/xmlsec

EXTRA_DIST = \
	testDSig.sh \
	testEnc.sh \
	testKeys.sh \
	keys \
	01-phaos-xmlenc-3 \
	aleksey-xmldsig-01 \
	aleksey-xmlenc-01 \
	merlin-exc-c14n-one \
	merlin-xmldsig-twenty-three \
	merlin-xmlenc-five \
	merlin-xpath-filter2-three \
	merlin-exc-c14n-one \
	merlin-c14n-three  \
	$(NULL)

check: check-km check-dsig check-enc
	@echo "-------------------------- ATTENTION -----------------------------------"
	@echo "--- 1) Some of the following tests use resources located on external ---"
	@echo "--- HTTP servers. If you have no Internet connection or the external ---"
	@echo "--- resource is not responding then the test will fail.              ---"
	@echo "--- 2) The test fails if corresponding feature(s) is disabled.       ---"
	@echo "--- Please, don't be surprised that many XML Encryption tests fails  ---"
	@echo "--- when you use OpenSSL 0.9.6 (see the FAQ for details)             ---"
	@echo "-------------------------- ATTENTION -----------------------------------"

check-km: $(XMLSEC_APP)
if XMLSEC_WITH_SKM_TEST
	@$(top_srcdir)/tests/testKeys.sh $(top_srcdir)/tests $(XMLSEC_APP) 
	@echo
else
	@echo "Simple Keys Manager support disabled"
endif 	

check-dsig: $(XMLSEC_APP)
if XMLSEC_WITH_XMLDSIG_TEST	
	@$(top_srcdir)/tests/testDSig.sh $(top_srcdir)/tests $(XMLSEC_APP) 
	@echo
else
	@echo "XML DSig support disabled"
endif	

check-enc: $(XMLSEC_APP)
if XMLSEC_WITH_XMLENC_TEST
	@$(top_srcdir)/tests/testEnc.sh $(top_srcdir)/tests $(XMLSEC_APP) 
	@echo
else
	@echo "XML Enc support disabled"
endif

memcheck-res: 
	@grep -i lost /tmp/*.log | sed 's/==.*== *//' | sort -u
	@grep -i leak /tmp/*.log | sed 's/==.*== *//' | sort -u

	