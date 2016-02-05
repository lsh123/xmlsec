#
#
#
NULL=
MODULE=xmlsec
SOURCE_DIR=$(top_srcdir)/src
SOURCE_DIR2=$(top_builddir)/src
INCLUDE_DIR=$(top_srcdir)/include
INCLUDE_DIR2=$(top_builddir)/include


EXTRA_DIST = \
	src \
	images \
	$(NULL)

SCAN_DIR=$(builddir)
TMPL_DIR=$(builddir)/tmpl.tmp
SGML_DIR=$(builddir)/sgml.tmp
XML_DIR=$(builddir)/xml.tmp
EXAMPLES_DIR=$(SGML_DIR)/examples
DOC_SOURCE_DIR=$(builddir)/code

#
# We need to pre-process original source files
# because gtkdoc does not understand some C features
#
DOC_SOURCE_FILES=\
	$(shell find $(SOURCE_DIR) -name '*.c' -print )  \
	$(shell find $(SOURCE_DIR2) -name '*.c' -print )  \
	$(shell find $(INCLUDE_DIR) -name '*.h' -a ! -name "symbols.h" -print ) \
	$(shell find $(INCLUDE_DIR2) -name '*.h' -a ! -name "symbols.h" -print )

EXAMPLES_SOURCE_DIR=$(top_srcdir)/examples
EXAMPLES_SOURCE_FILES=\
	$(shell find $(EXAMPLES_SOURCE_DIR) -name '*.c' -print) \
	$(shell find $(EXAMPLES_SOURCE_DIR) -name '*.xml' -print) 

REMOVE_GTKDOCLINK=$(top_srcdir)/scripts/remove-gtkdoclink.pl

# do nothing for all
all:

docs: sgml html clean-sources
	@(  echo "Cleaning up result files"; \
	    $(PERL) $(REMOVE_GTKDOCLINK) `find . -name "*.html" -print` \
	)

# need to cleanup "bad" chars
html: sgml $(srcdir)/src/xmlsec.sgml $(srcdir)/src/chapters xmlsec-index
	$(CP) -u $(srcdir)/src/xmlsec.sgml $(SGML_DIR)/xmlsec-main.sgml
	$(CP) -ru $(srcdir)/src/chapters $(SGML_DIR)/
	-$(GTKDOC_MKHTML) xmlsec $(SGML_DIR)/xmlsec-main.sgml

#
# Prepeare sgml files from sources for each library. We are also
# doing some "magic" here by automatically adding links to XML DSig and 
# XML Enc specification, we also remove "Ptr" from the end of the link
# targets to make more references
#
sgml: templates $(SGML_DIR)/.sentinel
	$(GTKDOC_MKDB) --module=xmlsec \
			--main-sgml-file=$(SGML_DIR)/xmlsec-base.sgml \
			--output-dir=$(SGML_DIR)/ \
		    --tmpl-dir=$(TMPL_DIR)/base \
		    --source-dir=$(DOC_SOURCE_DIR)/src/base \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/base
	$(GTKDOC_MKDB) --module=xmlsec-openssl \
		    --main-sgml-file=$(SGML_DIR)/xmlsec-openssl.sgml \
		    --tmpl-dir=$(TMPL_DIR)/openssl \
		    --output-dir=$(SGML_DIR)/openssl \
		    --source-dir=$(DOC_SOURCE_DIR)/src/openssl \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/openssl
	$(GTKDOC_MKDB) --module=xmlsec-gnutls \
		    --main-sgml-file=$(SGML_DIR)/xmlsec-gnutls.sgml \
		    --tmpl-dir=$(TMPL_DIR)/gnutls \
		    --output-dir=$(SGML_DIR)/gnutls \
		    --source-dir=$(DOC_SOURCE_DIR)/src/gnutls \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/gnutls
	$(GTKDOC_MKDB) --module=xmlsec-gcrypt \
		    --main-sgml-file=$(SGML_DIR)/xmlsec-gcrypt.sgml \
		    --tmpl-dir=$(TMPL_DIR)/gcrypt \
		    --output-dir=$(SGML_DIR)/gcrypt \
		    --source-dir=$(DOC_SOURCE_DIR)/src/gcrypt \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/gcrypt
	$(GTKDOC_MKDB) --module=xmlsec-nss \
		    --main-sgml-file=$(SGML_DIR)/xmlsec-nss.sgml \
		    --tmpl-dir=$(TMPL_DIR)/nss \
		    --output-dir=$(SGML_DIR)/nss \
		    --source-dir=$(DOC_SOURCE_DIR)/src/nss \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/nss
	$(GTKDOC_MKDB) --module=xmlsec-mscrypto \
		    --main-sgml-file=$(SGML_DIR)/xmlsec-mscrypto.sgml \
		    --tmpl-dir=$(TMPL_DIR)/mscrypto \
		    --output-dir=$(SGML_DIR)/mscrypto \
		    --source-dir=$(DOC_SOURCE_DIR)/src/mscrypto \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/mscrypto
	(for i in `find $(SGML_DIR) -name "*.sgml" -print` ; do \
			echo "Fixing up '$$i'" ; \
	        cat $$i | \
	          sed 's!\(<dsig:\)\([^/]*\)\(\/>\)!\&lt;dsig:\2\/\&gt;!g' | \
	          sed 's!\(<enc:\)\([^/]*\)\(\/>\)!\&lt;enc:\2\/\&gt;!g' | \
	          sed 's!\(<dsig:\)\(\w*\)\(>\)!\&lt;dsig:\2\/\&gt;!g' | \
	          sed 's!\(<enc:\)\(\w*\)\(>\)!\&lt;enc:\2\/\&gt;!g' | \
	          sed 's!\(&lt;dsig:\)\([^/]*\)\(\/&gt;\)!<ulink URL=\"http://www.w3.org/TR/xmldsig-core/#sec-\2\">\1\2\3</ulink>!g' | \
	          sed 's!\(&lt;enc:\)\([^/]*\)\(\/&gt;\)!<ulink URL=\"http://www.w3.org/TR/xmlenc-core/#sec-\2\">\1\2\3</ulink>!g' | \
	          sed 's!<para \/>!<para></para>!g' | \
	          sed 's!linkend=\"\(.*\)Ptr\"!linkend=\"\1\"!g' | \
	          sed 's!<colspec [^/]*\/>!!g' | \
	          $(PERL) -pe 's!para>\n!para>!g' > \
	          $$i.tmp; \
	        mv -f $$i.tmp $$i; \
	 done);

templates: scan $(TMPL_DIR)/.sentinel
	$(GTKDOC_MKTMPL) --module=xmlsec \
			--output-dir=$(TMPL_DIR)/base
	$(GTKDOC_MKTMPL) --module=xmlsec-openssl \
		    --output-dir=$(TMPL_DIR)/openssl
	$(GTKDOC_MKTMPL) --module=xmlsec-gnutls \
		    --output-dir=$(TMPL_DIR)/gnutls
	$(GTKDOC_MKTMPL) --module=xmlsec-gcrypt \
		    --output-dir=$(TMPL_DIR)/gcrypt
	$(GTKDOC_MKTMPL) --module=xmlsec-nss \
		    --output-dir=$(TMPL_DIR)/nss
	$(GTKDOC_MKTMPL) --module=xmlsec-mscrypto \
		    --output-dir=$(TMPL_DIR)/mscrypto

scan: doc_sources example_sources
	$(GTKDOC_SCAN) --module=xmlsec \
		    --rebuild-sections \
		    --output-dir=$(SCAN_DIR) \
		    --source-dir=$(DOC_SOURCE_DIR)/src/base \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/base
	$(GTKDOC_SCAN) --module=xmlsec-openssl \
		    --rebuild-sections \
		    --output-dir=$(SCAN_DIR) \
		    --source-dir=$(DOC_SOURCE_DIR)/src/openssl \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/openssl
	$(GTKDOC_SCAN) --module=xmlsec-gnutls \
		    --rebuild-sections \
		    --output-dir=$(SCAN_DIR) \
		    --source-dir=$(DOC_SOURCE_DIR)/src/gnutls \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/gnutls
	$(GTKDOC_SCAN) --module=xmlsec-gcrypt \
		    --rebuild-sections \
		    --output-dir=$(SCAN_DIR) \
		    --source-dir=$(DOC_SOURCE_DIR)/src/gcrypt \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/gcrypt
	$(GTKDOC_SCAN) --module=xmlsec-nss \
		    --rebuild-sections \
		    --output-dir=$(SCAN_DIR) \
		    --source-dir=$(DOC_SOURCE_DIR)/src/nss \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/nss
	$(GTKDOC_SCAN) --module=xmlsec-mscrypto \
		    --rebuild-sections \
		    --output-dir=$(SCAN_DIR) \
		    --source-dir=$(DOC_SOURCE_DIR)/src/mscrypto \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/mscrypto

#
# Prepare source files by coping them to "code" folder and 
# removing XMLSEC_EXPORT_* stuff that makes gtkdoc crazy
#
doc_sources: $(DOC_SOURCE_FILES) $(DOC_SOURCE_DIR)/.sentinel $(DOC_SOURCE_DIR)/src/base/.sentinel $(DOC_SOURCE_DIR)/include/xmlsec/base/.sentinel
	@echo "Preprocessing source files into '$(DOC_SOURCE_DIR)' ..." 
	@( \
	for i in $(DOC_SOURCE_FILES) ; do \
		folder_name=`echo "$$i" | \
			sed 's#$(top_srcdir)/##' | \ 
			sed 's#$(top_builddir)/##' | \ 
			sed 's#/[^/]*$$##'`; \
	    file_name=`echo "$$i" | \
	    	sed 's#.*/##'`; \
	    mkdir -p "$(DOC_SOURCE_DIR)/$$folder_name"; \
	    cat "$$i" | \
		    sed 's/#if.*//' | \
		    sed 's/#el.*//' | \
		    sed 's/#end.*//' | \
		    sed 's/XMLSEC_CRYPTO_EXPORT//' | \
		    sed 's/XMLSEC_EXPORT_VAR//' | \
		    sed 's/XMLSEC_EXPORT//' | \
		    sed 's/XMLSEC_ERRORS_PRINTF_ATTRIBUTE//' > \
		    $(DOC_SOURCE_DIR)/$$folder_name/$$file_name; \
	done);
	-@mv -f $(DOC_SOURCE_DIR)/src/*.c $(DOC_SOURCE_DIR)/src/base
	-@mv -f $(DOC_SOURCE_DIR)/include/xmlsec/*.h $(DOC_SOURCE_DIR)/include/xmlsec/base
	-@rm -f $(DOC_SOURCE_DIR)/include/xmlsec/*/symbols.h

#
# Create index for all functions. For macros and defines need to add -CAPS suffix
#
xmlsec-index: scan $(SGML_DIR)/.sentinel
	@grep -h '<NAME>.*</NAME>' $(SCAN_DIR)/xmlsec-*decl.txt | \
		grep -v '<NAME>extern</NAME>' | \
		sort -u | \
		sed 's#_#-#g' | \
		sed 's#<NAME>\([^-]*\)-\([^<]*\)</NAME>#<listitem><para><link linkend=\"\1-\2-CAPS\">\1-\2</link></para></listitem>#g' | \
		sed 's#<NAME>\([^<]*\)</NAME>#<listitem><para><link linkend=\"\1\">\1</link></para></listitem>#g' > \
		$(SGML_DIR)/xmlsec-index.sgml

#
# The following code converts C example file to sgml RefEntry files.
# We get file title from a string "XML Security Library example: ..."
# which is usually placed at the top of the file. Also all "unsafe" xml 
# characters (<, >, &) are escaped. 
#
example_sources: $(EXAMPLES_DIR)/.sentinel
	@(for i in $(EXAMPLES_SOURCE_FILES) ; do \
	    file_name=`echo $$i | sed 's#.*/##' | sed 's#\..*$$##'`; \
	    file_ext=`echo $$i | sed 's#.*/##' | sed 's#.*\.##'`; \
	    echo Converting $$file_name.$$file_ext to $$file_name.sgml ...; \
	    file_title=`cat $$i | grep 'XML Security Library example: ' | sed 's#^.*: *##'`; \
	    echo "<sect2 id=\"xmlsec-example-$$file_name\" >" > \
	        $(EXAMPLES_DIR)/$$file_name.sgml; \
	    echo "<title>$$file_name.$$file_ext</title><para><informalexample><programlisting>" >> \
		    $(EXAMPLES_DIR)/$$file_name.sgml; \
	    cat $$i | \
		sed "s#&#\&amp;#g" | \
		sed "s#<#\&lt;#g" | \
		sed "s#>#\&gt;#g" >> \
		    $(EXAMPLES_DIR)/$$file_name.sgml; \
	    echo "</programlisting></informalexample></para></sect2>" >> \
		    $(EXAMPLES_DIR)/$$file_name.sgml; \
	done);

# A single pattern rule will create all appropriate folders as required
# otherwise make (annoyingly) deletes it
.PRECIOUS: %/.sentinel
%/.sentinel:
	mkdir -p ${@D}
	touch $@

dist-hook:
	@cp -p $(srcdir)/*.html $(srcdir)/*.png $(distdir)

clean: clean-sources
	-@rm -rf $(DOC_SOURCE_DIR) $(SCAN_DIR)/*.txt $(TMPL_DIR) $(SGML_DIR) $(XML_DIR)
	-@rm -f *.stamp *.types index.sgml 

clean-sources:
	-@rm -rf $(DOC_SOURCE_DIR) $(EXAMPLES_DIR)

maintainer-clean-local: clean
	-@rm -f *.html

