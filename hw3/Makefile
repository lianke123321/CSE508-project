# Adrian's Makefile for CSE 508 project 3

all: clean pbproxy echo_server echo_client

pbproxy: pbproxy.c
	gcc -g pbproxy.c -o pbproxy.o

echo_server: echo_server.c
	gcc -g echo_server.c -o echo_server.o

echo_client: echo_client.c
	gcc -g echo_client.c -o echo_client.o

clean:
	rm -f *~ *.o *.out
