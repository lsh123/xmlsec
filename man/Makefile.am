NULL =

man_MANS = \
	xmlsec1.1 \
	xmlsec1-config.1 \
	$(NULL)

EXTRA_DIST = \
	xmlsec1.1 \
	xmlsec1-config.1 \
	$(NULL)

XMLSEC_PROGRAM=$(top_builddir)/apps/xmlsec1
XMLSEC_CONFIG_PROGRAM=$(top_builddir)/xmlsec1-config
XMLSEC_HTML=$(top_builddir)/docs/xmlsec-man.html

all:

docs: man-clean man $(XMLSEC_HTML)
	

man-clean:
	@rm -rf $(man_MANS)

man: $(man_MANS) 

$(XMLSEC_HTML): xmlsec1.1
	man2html xmlsec1.1 | \
		  grep -v '^Content-type: text/html' | \
		  tr "[:cntrl:]" " " > \
		  $(XMLSEC_HTML)

xmlsec1.1:
	@rm -f xmlsec1.1
	help2man --help-option=--help-all --no-info \
		  --name="sign, verify, encrypt and decrypt XML documents" \
		  --version-option=--version \
		  $(XMLSEC_PROGRAM) > xmlsec1.1

xmlsec1-config.1:
	@chmod 766 $(XMLSEC_CONFIG_PROGRAM)
	@rm -f xmlsec1-config.1
	help2man --help-option=--help --no-info \
		  --name="detail installed version of xmlsec library" \
		  --version-option=--version \
		  $(XMLSEC_CONFIG_PROGRAM) > xmlsec1-config.1

$(XMLSEC_PROGRAM): 
	@cd ../apps;make

clean:
	
