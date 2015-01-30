VPATH = src

CC = gcc
LD = gcc
CFLAGS = -pipe -Wall -Wno-unused -O3 -g #-arch i386
LDFLAGS = #-arch i386

OS_LAYER = osl-osx.c

all: lld2d lld2test

include src/common.mk

depend:
	$(CC) $(CFLAGS) -M $(DCFILES) >.depend
	$(CC) $(CFLAGS) -M $(TCFILES) >>.depend

clear:
	rm -f *.o lld2d lld2test

-include .depend
