AC_INIT
AM_INIT_AUTOMAKE(pcap_tools, 0.0.1)
AC_PREREQ(2.59)
AC_PROG_RANLIB
AC_PROG_LIBTOOL

AC_LANG([C])

AC_CHECK_HEADERS(stdio.h unistd.h stdlib.h string.h)

AC_CHECK_LIB(pthread, main, , AC_MSG_ERROR([libpthread not found]))
AC_CHECK_HEADERS([pthread.h] , , AC_MSG_ERROR([pthread headers not found]))

AC_CHECK_LIB(pcap, main, , AC_MSG_ERROR([libpcap not found]))
AC_CHECK_HEADERS([pcap.h] , , AC_MSG_ERROR([pcap headers not found]))

AC_CHECK_LIB(z, main, , AC_MSG_ERROR([libz not found]))
AC_CHECK_HEADERS([zlib.h] , , AC_MSG_ERROR([libz headers not found]))


AC_CONFIG_FILES(Makefile packzip/Makefile tools/Makefile)
AC_OUTPUT
