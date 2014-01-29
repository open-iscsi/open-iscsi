AM_CFLAGS =	-I${top_srcdir}/src/unix		\
		-I${top_srcdir}/src/uip			\
		-I${top_srcdir}/src/apps/dhcpc		\
		-I${top_srcdir}/src/apps/brcm-iscsi	\
		-I${top_srcdir}/../include		\
		-I${top_srcdir}/../usr

noinst_LIBRARIES = lib_apps_brcm_iscsi.a

lib_apps_brcm_iscsi_a_SOURCES = brcm_iscsi.c

lib_apps_brcm_iscsi_a_CFLAGS =	$(AM_CFLAGS)             \
				-DBYTE_ORDER=@ENDIAN@
