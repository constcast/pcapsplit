SUBDIRS = modules tools

bin_PROGRAMS=pcapsplit

pcapsplit_SOURCES=main.c

AM_CFLAGS=-Wall -Werror -O0 -g -pg -I$(top_srcdir)
AM_LDFLAGS=

pcapsplit_LDADD=modules/libmodules.a tools/libtools.a -lpcap
