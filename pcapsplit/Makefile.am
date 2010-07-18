SUBDIRS = modules tools

bin_PROGRAMS=pcapsplit

pcapsplit_SOURCES=main.c packet.h dumping_module.h \
	dumping_module.c iniparser.h iniparser.c conf.h conf.c \
	module_list.h module_list.c 

AM_CFLAGS=-Wall -Werror -g -I$(top_srcdir)
AM_LDFLAGS=

pcapsplit_LDADD=modules/libmodules.a tools/libtools.a -lpcap
