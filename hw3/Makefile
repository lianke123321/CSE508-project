# Adrian's Makefile for CSE 508 project 3

all: clean pbproxy tmp_server

mydump: pbproxy.c
	gcc -g pbproxy.c -o pbproxy

tmp_server: tmp_server.c
	gcc -g tmp_server.c -o tmp_server

clean:
	rm -f *~ *.o *.out pbproxy tmp_server
