SUBDIRS= src

EXTRA_DIST = build_date

build_date:
	echo 'char *build_date = "'`date`'";' > build_date.c
	echo 'char *build_date;'> build_date.h

manprefix = /usr/share
mandir = ${manprefix}/man
logdir = /etc/logrotate.d

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am install-man install-log install-brcm

install-man:
	cat docs/iscsiuio.8 | GZIP=$(GZIP_ENV) gzip -c > iscsiuio.8.gz
	$(INSTALL_PROGRAM) iscsiuio.8.gz $(mandir)/man8

install-log:
	$(INSTALL_PROGRAM) iscsiuiolog $(logdir)

install-brcm:
	-rm -f $(sbindir)/brcm_iscsiuio
	-ln -s $(sbindir)/iscsiuio $(sbindir)/brcm_iscsiuio
