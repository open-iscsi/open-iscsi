dnl iscsiuio uIP user space stack configure.ac file
dnl
dnl Copyright (c) 2004-2013 Broadcom Corporation
dnl Copyright (c) 2014, QLogic Corporation
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation.
dnl
dnl Written by: Eddie Wai (eddie.wai@broadcom.com)
dnl             Benjamin Li  (benli@broadcom.com)
dnl

PACKAGE=iscsiuio
VERSION=0.7.8.6

AC_INIT([iscsiuio], [0.7.8.6], [QLogic-Storage-Upstream@cavium.com])

AM_INIT_AUTOMAKE
AC_CONFIG_HEADER(config.h)
AC_PATH_PROGS(BASH, bash)

AC_PROG_CC
AM_PROG_CC_C_O

AC_PROG_RANLIB

AC_GNU_SOURCE
AC_PROG_INSTALL
AC_PROG_GCC_TRADITIONAL

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_CHECK_TYPES(int8_t)
AC_CHECK_TYPES(uint8_t)
AC_CHECK_TYPES(int16_t)
AC_CHECK_TYPES(uint16_t)
AC_CHECK_TYPES(int32_t)
AC_CHECK_TYPES(uint32_t)
AC_CHECK_TYPES(int64_t)
AC_CHECK_TYPES(uint64_t)
AC_CHECK_SIZEOF(short, 2)
AC_CHECK_SIZEOF(int, 4)
AC_CHECK_SIZEOF(long, 4)

AC_C_BIGENDIAN(AC_SUBST([ENDIAN],[BIG]),AC_SUBST([ENDIAN],[LITTLE]))

AC_LIBTOOL_DLOPEN

# libtool stuff
AC_PROG_LIBTOOL

: ${CFLAGS:="-O2"}
CFLAGS="${CFLAGS} -Wall"
## check for --enable-debug first before checking CFLAGS before
## so that we don't mix -O and -g
AC_ARG_ENABLE(debug,
[  --enable-debug          Turn on compiler debugging information (default=no)],
    [if eval "test x$enable_debug = xyes"; then
        CFLAGS="${CFLAGS} -g -O0"
    fi])
AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])
## check for systemd support, default on
AC_ARG_WITH([systemd],
	    AS_HELP_STRING([--without-systemd], [Build without systemd]),
    [case "${withval}" in
     yes) with_libsystemd=yes ;;
     no)  wth_libsystemd=no ;;
     *)   AC_MSG_ERROR([bad value $withval for --with-systemd]) ;;
     esac],[with_libsystemd=auto])
AS_IF([test "$with_libsystemd" != no],[
    PKG_CHECK_MODULES([LIBSYSTEMD],[libsystemd],[LIBS="${LIBS} $LIBSYSTEMD_LIBS"],[
        if test "$with_libsystemd" = yes; then
            AC_MSG_ERROR([could not find libsystemd using pkg-config])
	else
            CFLAGS="${CFLAGS} -DNO_SYSTEMD"
	fi
    ])
],[
    CFLAGS="${CFLAGS} -DNO_SYSTEMD"
])

AC_CONFIG_COMMANDS([default],[[
    if [ -n "$SOURCE_DATE_EPOCH" ] ; then
        echo 'char *build_date = "'`LC_ALL=C.UTF-8 date --date=@$SOURCE_DATE_EPOCH -u`'";' > src/unix/build_date.c
    else
        echo 'char *build_date = "'`date`'";' > src/unix/build_date.c
    fi
    echo 'extern char *build_date;'> src/unix/build_date.h
]],[[]])

AC_PREFIX_DEFAULT()

AC_OUTPUT([Makefile
src/Makefile
src/apps/Makefile
src/apps/dhcpc/Makefile
src/apps/brcm-iscsi/Makefile
src/uip/Makefile
src/unix/Makefile
src/unix/libs/Makefile])
