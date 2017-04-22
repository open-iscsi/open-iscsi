AM_CFLAGS = -I${top_srcdir}/src/uip		\
	   -I${top_srcdir}/src/unix		\
	   -I${top_srcdir}/src/unix/libs	\
           -I${top_srcdir}/src/apps/dhcpc	\
           -I${top_srcdir}/../include		\
           -I${top_srcdir}/../usr

noinst_LIBRARIES = lib_iscsiuio_hw_cnic.a

lib_iscsiuio_hw_cnic_a_SOURCES =	../build_date.c \
					cnic.c 		\
					bnx2.c		\
					bnx2x.c		\
					qedi.c
