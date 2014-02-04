# This Makefile will work only with GNU make.

OPTFLAGS ?= -O2 -g
CFLAGS += $(OPTFLAGS) $(WARNFLAGS) -fno-inline -Wall -Wstrict-prototypes

SYSDEPS_OBJS=sysdeps.o

all: $(SYSDEPS_OBJS)

clean:
	$(RM) *.o .depend

depend:
	$(CC) $(CFLAGS) -M `ls *.c` > .depend

-include .depend
