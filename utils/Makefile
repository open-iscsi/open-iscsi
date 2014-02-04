# This Makefile will work only with GNU make.

OPTFLAGS ?= -O2 -g
CFLAGS += $(OPTFLAGS) -fno-inline -Wall -Wstrict-prototypes
PROGRAMS = iscsi-iname

all: $(PROGRAMS)

iscsi-iname: md5.o iscsi-iname.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(DBM_LIB) -o $@

clean:
	$(RM) *.o $(PROGRAMS) .depend

depend:
	$(GCC) $(CFLAGS) -M `ls *.c` > .depend

-include .depend
