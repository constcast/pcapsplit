bin_PROGRAMS=pcapsplit

pcapsplit_SOURCES=main.c packet.h dumping_module.h \
	dumping_module.c size_dumper.h size_dumper.c \
	iniparser.h iniparser.c conf.h conf.c

AM_CFLAGS=-Wall -Werror -g
AM_LDFLAGS=

pcapsplit_LDADD=-lpcap
