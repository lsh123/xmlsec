NULL =

EXTRA_DIST = \
    xmlsec.1 \
    xmlsec-config.1 \
    $(NULL)

man_MANS = \
    xmlsec.1 \
    xmlsec-config.1 \
    $(NULL)

XMLSEC_PROGRAM=../apps/xmlsec
XMLSEC_CONFIG_PROGRAM=../xmlsec-config
XMLSEC_HTML=../docs/xmlsec-man.html

all: $(man_MANS) $(XMLSEC_HTML)

$(XMLSEC_HTML): xmlsec.1
	man2html xmlsec.1 | \
		  grep -v '^Content-type: text/html' | \
		  tr "[:cntrl:]" " " > \
		  $(XMLSEC_HTML)

xmlsec.1: $(XMLSEC_PROGRAM)
	help2man --help-option=--help-all \
		  --version-option=--version \
		  $(XMLSEC_PROGRAM) > xmlsec.1

xmlsec-config.1: $(XMLSEC_CONFIG_PROGRAM)
	@chmod 766 $(XMLSEC_CONFIG_PROGRAM)
	help2man --help-option=--help \
		  --version-option=--version \
		  $(XMLSEC_CONFIG_PROGRAM) > xmlsec-config.1
	
