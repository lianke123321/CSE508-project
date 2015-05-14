# Adrian's Makefile for CSE 508 project 3

all: clean quantuminject

quantuminject: quantuminject.c
	gcc -g quantuminject.c -lpcap -lpcre -o quantuminject.o

clean:
	rm -f *~ *.o *.out
