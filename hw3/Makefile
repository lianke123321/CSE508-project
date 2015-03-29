# Adrian's Makefile for CSE 508 project 3

all: clean pbproxy echo_server echo_client

pbproxy: pbproxy.c
	gcc -g pbproxy.c -o pbproxy

echo_server: echo_server.c
	gcc -g echo_server.c -o echo_server

echo_client: echo_client.c
	gcc -g echo_client.c -o echo_client

clean:
	rm -f *~ *.o *.out pbproxy echo_server echo_client
