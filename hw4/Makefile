# Adrian's Makefile for CSE 508 project 3

all: clean quantuminject quantumdetect

quantuminject: quantuminject.c
	gcc -g quantuminject.c -lpcap -lpcre -o quantuminject.o

quantumdetect: quantumdetect.c
	gcc -g quantumdetect.c -lpcap -o quantumdetect.o

clean:
	rm -f *~ *.o *.out
