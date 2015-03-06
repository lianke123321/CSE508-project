# Adrian's first Makefile for CSE 508 project 2

all: clean mydump

mydump: mydump.c
	gcc -g mydump.c -lpcap -o mydump

clean:
	rm -f *~ *.o *.out mydump