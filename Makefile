VPATH = src

CC = gcc
LD = gcc
CFLAGS = -pipe -Wall -Wno-unused -O3 -g -D_DARWIN_C_SOURCE=1
LDFLAGS =

OS_LAYER = osl-osx.c

all: lld2d lld2test

include src/common.mk

depend:
	$(CC) $(CFLAGS) -M $(DCFILES) >.depend
	$(CC) $(CFLAGS) -M $(TCFILES) >>.depend

clear:
	rm -f *.o lld2d lld2test

-include .depend
