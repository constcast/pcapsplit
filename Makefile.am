bin_PROGRAMS=pcapsplit

pcapsplit_SOURCES=main.c packet.h dumping_module.h \
	dumping_module.c size_dumper.h size_dumper.c \
	dumping_list.c dumping_list.h iniparser.h iniparser.c

AM_CFLAGS=-Wall -Werror -g
AM_LDFLAGS=

pcapsplit_LDADD=-lpcap
