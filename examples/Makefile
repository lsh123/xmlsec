#
#
#
PROGRAMS_SIGN   = sign1 sign2 sign3
PROGRAMS_VERIFY = verify1 verify2 verify3 verify4
PROGRAMS_ENC    = encrypt1 encrypt2 encrypt3
PROGRAMS_DEC    = decrypt1 decrypt2 decrypt3
PROGRAMS = \
	$(PROGRAMS_SIGN) \
	$(PROGRAMS_VERIFY) \
	$(PROGRAMS_ENC) \
	$(PROGRAMS_DEC) \
	xmldsigverify

CC	= gcc
CFLAGS	+= -g $(shell xmlsec1-config --cflags) -DUNIX_SOCKETS -Wall -Wextra
LDLIBS	+= -g $(shell xmlsec1-config --libs)

all: $(PROGRAMS)

clean:
	rm -rf $(PROGRAMS)

check: check-sign check-verify check-enc check-dec

check-sign: $(PROGRAMS_SIGN)
	./sign1    sign1-tmpl.xml    rsakey.pem
	./sign2    sign2-doc.xml     rsakey.pem
	./sign3    sign3-doc.xml     rsakey.pem rsacert.pem

check-verify: $(PROGRAMS_VERIFY)
	./verify1  sign1-res.xml     rsapub.pem
	./verify1  sign2-res.xml     rsapub.pem
	./verify2  sign1-res.xml     rsakey.pem
	./verify2  sign2-res.xml     rsakey.pem
	./verify3  sign3-res.xml     ca2cert.pem cacert.pem
	./verify4  verify4-res.xml   ca2cert.pem cacert.pem

check-enc: $(PROGRAMS_ENC)
	./encrypt1 encrypt1-tmpl.xml deskey.bin
	./encrypt2 encrypt2-doc.xml  deskey.bin
	./encrypt3 encrypt3-doc.xml  rsakey.pem

check-dec: $(PROGRAMS_DEC)
	./decrypt1 encrypt1-res.xml  deskey.bin
	./decrypt1 encrypt2-res.xml  deskey.bin
	./decrypt2 encrypt1-res.xml  deskey.bin
	./decrypt2 encrypt2-res.xml  deskey.bin
	./decrypt3 encrypt1-res.xml
	./decrypt3 encrypt2-res.xml
	./decrypt3 encrypt3-res.xml
