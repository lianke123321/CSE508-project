# Adrian's first Makefile for CSE 508 project 2

all: clean mydump refdump

mydump: mydump.c
	gcc -g mydump.c -lpcap -o mydump

refdump: refdump.c
	gcc -g refdump.c -lpcap -o refdump

clean:
	rm -f *~ *.o *.out mydump refdump