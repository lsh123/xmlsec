#
#
#
PROGRAM		 = enc2
PWD		 = $(shell pwd)
cc	 	 = gcc
CC	 	 = gcc
LD	 	 = gcc


CFLAGS		+= -g $(shell xmlsec-config --cflags)
LIBS 		+= -static $(shell xmlsec-config --libs) 

$(PROGRAM):  $(PROGRAM).c
	$(cc) $(LDFLAGS) $(CFLAGS) -o $(PROGRAM) $(PROGRAM).c $(LIBRARY) $(LIBS) 


clean:
	@rm -rf $(PROGRAM)

