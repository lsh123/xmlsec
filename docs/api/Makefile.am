#
#
#
NULL=
MODULE=xmlsec
SOURCE_DIR=$(top_srcdir)/src
INCLUDE_DIR=$(top_srcdir)/include

EXTRA_DIST = \
	chapters \
	images \
	$(NULL)

#
# We need to pre-process original source files
# because gtkdoc does not understand some C features
#
DOC_SOURCE_DIR=$(builddir)/code
DOC_SOURCE_FILES=\
	$(shell find $(SOURCE_DIR) -name '*.c' -print )  \
	$(shell find $(INCLUDE_DIR) -name '*.h' -a ! -name "symbols.h" -print )

EXAMPLES_DIR=$(builddir)/examples
EXAMPLES_SOURCE_DIR=$(top_srcdir)/examples
EXAMPLES_SOURCE_FILES=\
	$(shell find $(EXAMPLES_SOURCE_DIR) -name '*.c' -print) \
	$(shell find $(EXAMPLES_SOURCE_DIR) -name '*.xml' -print) 

# do nothing for all
all:

docs: sgml html clean-sources

# need to cleanup "bad" chars
html: sgml $(srcdir)/xmlsec.sgml xmlsec-index
	$(CP) -u $(srcdir)/xmlsec.sgml $(builddir)/xmlsec.sgml
	$(CP) -ru $(srcdir)/chapters $(builddir)/
	$(GTKDOC_MKHTML) xmlsec $(builddir)/xmlsec.sgml

#
# Prepeare sgml files from sources for each library. We are also
# doing some "magic" here by automatically adding links to XML DSig and 
# XML Enc specification, we also remove "Ptr" from the end of the link
# targets to make more references
#
sgml: templates
	$(GTKDOC_MKDB) --module=xmlsec \
		    --source-dir=$(DOC_SOURCE_DIR)/src/base \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/base
	$(GTKDOC_MKDB) --module=xmlsec-openssl \
		    --main-sgml-file=xmlsec-openssl.sgml \
		    --tmpl-dir=tmpl/openssl \
		    --output-dir=sgml/openssl \
		    --source-dir=$(DOC_SOURCE_DIR)/src/openssl \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/openssl
	$(GTKDOC_MKDB) --module=xmlsec-gnutls \
		    --main-sgml-file=xmlsec-gnutls.sgml \
		    --tmpl-dir=tmpl/gnutls \
		    --output-dir=sgml/gnutls \
		    --source-dir=$(DOC_SOURCE_DIR)/src/gnutls \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/gnutls
	$(GTKDOC_MKDB) --module=xmlsec-gcrypt \
		    --main-sgml-file=xmlsec-gcrypt.sgml \
		    --tmpl-dir=tmpl/gcrypt \
		    --output-dir=sgml/gcrypt \
		    --source-dir=$(DOC_SOURCE_DIR)/src/gcrypt \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/gcrypt
	$(GTKDOC_MKDB) --module=xmlsec-nss \
		    --main-sgml-file=xmlsec-nss.sgml \
		    --tmpl-dir=tmpl/nss \
		    --output-dir=sgml/nss \
		    --source-dir=$(DOC_SOURCE_DIR)/src/nss \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/nss
	$(GTKDOC_MKDB) --module=xmlsec-mscrypto \
		    --main-sgml-file=xmlsec-mscrypto.sgml \
		    --tmpl-dir=tmpl/mscrypto \
		    --output-dir=sgml/mscrypto \
		    --source-dir=$(DOC_SOURCE_DIR)/src/mscrypto \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/mscrypto
	(for i in `find xml -name "*.xml" -print` ; do \
	        cat $$i | \
	          sed 's!\(<dsig:\)\([^/]*\)\(\/>\)!\&lt;dsig:\2\/\&gt;!g' | \
	          sed 's!\(<enc:\)\([^/]*\)\(\/>\)!\&lt;enc:\2\/\&gt;!g' | \
	          sed 's!\(<dsig:\)\(\w*\)\(>\)!\&lt;dsig:\2\/\&gt;!g' | \
	          sed 's!\(<enc:\)\(\w*\)\(>\)!\&lt;enc:\2\/\&gt;!g' | \
	          sed 's!\(&lt;dsig:\)\([^/]*\)\(\/&gt;\)!<ulink URL=\"http://www.w3.org/TR/xmldsig-core/#sec-\2\">\1\2\3</ulink>!g' | \
	          sed 's!\(&lt;enc:\)\([^/]*\)\(\/&gt;\)!<ulink URL=\"http://www.w3.org/TR/xmlenc-core/#sec-\2\">\1\2\3</ulink>!g' | \
	          sed 's!linkend=\"\(.*\)Ptr\"!linkend=\"\1\"!g' > \
	          $$i.tmp; \
	        mv -f $$i.tmp $$i; \
	 done);

templates: scan
	$(GTKDOC_MKTMPL) --module=xmlsec
	$(GTKDOC_MKTMPL) --module=xmlsec-openssl \
		    --output-dir=tmpl/openssl
	$(GTKDOC_MKTMPL) --module=xmlsec-gnutls \
		    --output-dir=tmpl/gnutls
	$(GTKDOC_MKTMPL) --module=xmlsec-gcrypt \
		    --output-dir=tmpl/gcrypt
	$(GTKDOC_MKTMPL) --module=xmlsec-nss \
		    --output-dir=tmpl/nss
	$(GTKDOC_MKTMPL) --module=xmlsec-mscrypto \
		    --output-dir=tmpl/mscrypto

scan: doc_sources example_sources
	$(GTKDOC_SCAN) --module=xmlsec \
		    --rebuild-sections \
		    --source-dir=$(DOC_SOURCE_DIR)/src/base \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/base
	$(GTKDOC_SCAN) --module=xmlsec-openssl \
		    --rebuild-sections \
		    --source-dir=$(DOC_SOURCE_DIR)/src/openssl \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/openssl
	$(GTKDOC_SCAN) --module=xmlsec-gnutls \
		    --rebuild-sections \
		    --source-dir=$(DOC_SOURCE_DIR)/src/gnutls \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/gnutls
	$(GTKDOC_SCAN) --module=xmlsec-gcrypt \
		    --rebuild-sections \
		    --source-dir=$(DOC_SOURCE_DIR)/src/gcrypt \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/gcrypt
	$(GTKDOC_SCAN) --module=xmlsec-nss \
		    --rebuild-sections \
		    --source-dir=$(DOC_SOURCE_DIR)/src/nss \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/nss
	$(GTKDOC_SCAN) --module=xmlsec-mscrypto \
		    --rebuild-sections \
		    --source-dir=$(DOC_SOURCE_DIR)/src/mscrypto \
		    --source-dir=$(DOC_SOURCE_DIR)/include/xmlsec/mscrypto

#
# Prepare source files by coping them to "code" folder and 
# removing XMLSEC_EXPORT_* stuff that makes gtkdoc crazy
#
doc_sources: $(DOC_SOURCE_FILES)
	@echo "Preprocessing source files into '$(DOC_SOURCE_DIR)' ..." 
	@( \
	for i in $(DOC_SOURCE_FILES) ; do \
		folder_name=`echo $$i | sed 's#$(top_srcdir)/##' | sed 's#/[^/]*$$##'`; \
	    file_name=`echo $$i | sed 's#.*/##'`; \
	    mkdir -p "$(DOC_SOURCE_DIR)/$$folder_name"; \
	    cat $$i | \
		    sed 's/#if.*//' | \
		    sed 's/#el.*//' | \
		    sed 's/#end.*//' | \
		    sed 's/XMLSEC_CRYPTO_EXPORT//' | \
		    sed 's/XMLSEC_EXPORT_VAR//' | \
		    sed 's/XMLSEC_EXPORT//' | \
		    sed 's/XMLSEC_ERRORS_PRINTF_ATTRIBUTE//' > \
		    $(DOC_SOURCE_DIR)/$$folder_name/$$file_name; \
	done);
	-@mkdir -p $(DOC_SOURCE_DIR)/src/base
	-@mv -f $(DOC_SOURCE_DIR)/src/*.c $(DOC_SOURCE_DIR)/src/base
	-@mkdir -p $(DOC_SOURCE_DIR)/include/xmlsec/base
	-@mv -f $(DOC_SOURCE_DIR)/include/xmlsec/*.h $(DOC_SOURCE_DIR)/include/xmlsec/base
	-@rm -f $(DOC_SOURCE_DIR)/include/xmlsec/*/symbols.h

#
# Create index for all functions. For macros and defines need to add -CAPS suffix
#
xmlsec-index: scan
	@grep -h '<NAME>.*</NAME>' xmlsec-*decl.txt | \
		grep -v '<NAME>extern</NAME>' | \
		sort -u | \
		sed 's#_#-#g' | \
		sed 's#<NAME>\([^-]*\)-\([^<]*\)</NAME>#<listitem><para><link linkend=\"\1-\2-CAPS\">\1-\2</link></para></listitem>#g' | \
		sed 's#<NAME>\([^<]*\)</NAME>#<listitem><para><link linkend=\"\1\">\1</link></para></listitem>#g' > \
		xmlsec-index.sgml

#
# The following code converts C example file to sgml RefEntry files.
# We get file title from a string "XML Security Library example: ..."
# which is usually placed at the top of the file. Also all "unsafe" xml 
# characters (<, >, &) are escaped. 
#
example_sources:
	@mkdir -p $(EXAMPLES_DIR)
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

dist-hook:
	@cp -p $(srcdir)/*.html $(srcdir)/*.png $(srcdir)/*.sgml $(distdir)

clean: clean-sources
	-@rm -rf $(DOC_SOURCE_DIR)
	-@rm -rf sgml/*~ sgml/*.bak  
	-@rm -rf tmpl/*~ tmpl/*.bak  
	-@rm -rf *~ *.bak *.hierarchy *.signals *-unused.txt *.stamp

clean-sources:
	-@rm -rf $(DOC_SOURCE_DIR) $(EXAMPLES_DIR)

clean-local:
	-@rm -rf *~ *.bak *.hierarchy *.signals *-unused.txt

maintainer-clean-local: clean
	-@rm *.html *.txt
	-@rm -rf `find sgml -name "*.sgml" -print`

