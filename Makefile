LDFLAGS=

all: main.c
	gcc -o pcapsplit main.c -lpcap
