CFLAGS += -O2 -fno-inline -Wall -Wstrict-prototypes -g -I../include
PROGRAMS = iscsid iscsiadm

# sources shared between iscsid and iscsiadm
COMMON_SRCS = io.o auth.o login.o log.o md5.o sha1.o ddbm.o

all: $(PROGRAMS)

iscsid: $(COMMON_SRCS) iscsid.o ipc.o ctldev.o
	$(CC) $^ -ldb -o $@

iscsiadm: $(COMMON_SRCS) strings.o discovery.o iscsiadm.o
	$(CC) $^ -ldb -o $@

clean:
	rm -f *.o $(PROGRAMS)
