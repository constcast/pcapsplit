# Copyright (C) 2008 Lothar Braun <lothar@lobraun.de>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_INIT
AC_PREREQ(2.59)
AC_PROG_RANLIB
AM_INIT_AUTOMAKE(pcapsplit, 0.0b)

AC_CHECK_HEADERS(stdio.h stdlib.h unistd.h libgen.h sys/types.h ctype.h string.h)

# check for libpcap
AC_CHECK_HEADER([pcap.h],
                [],
                [AC_MSG_ERROR([*** could not find pcap.h. Please install libpcap.])])
AC_CHECK_LIB([pcap], [pcap_open_live],
             [LDFLAGS="$LDFLAGS -lpcap"
              AC_SUBST(LDFLAGS)],
             [AC_MSG_ERROR([*** could not find libpcap. Please install it.])])

AC_CONFIG_FILES([Makefile modules/Makefile])

AC_OUTPUT
