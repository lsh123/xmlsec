#
#
#
PROGRAM		 = xmldsigverify

cc	 	 = gcc
CC	 	 = gcc
LD	 	 = gcc

CFLAGS		+= -g -Wall $(shell xmlsec-config --cflags)
LDFLAGS		+= -g
LIBS 		+= -static $(shell xmlsec-config --libs) 

$(PROGRAM):  $(PROGRAM).c 
	$(cc) $(LDFLAGS) $(CFLAGS) -o $(PROGRAM) $(PROGRAM).c $(LIBRARY) $(LIBS) 

clean:
	@rm -rf $(PROGRAM)

