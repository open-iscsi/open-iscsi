CFLAGS += -O2 -fno-inline -Wall -Wstrict-prototypes -g -I../include
PROGRAMS = iscsid iscsiadm

all: $(PROGRAMS)

iscsid: io.o auth.o login.o iscsid.o ctldev.o log.o md5.o sha1.o ipc.o
	$(CC) $^ -o $@

iscsiadm: iscsiadm.o ctldev.o
	$(CC) $^ -o $@

clean:
	rm -f *.o $(PROGRAMS)
