# Adrian's Makefile for CSE 508 project 3

all: clean quantuminject quantumdetect

quantuminject: quantuminject.c
	gcc -g quantuminject.c -o quantuminject.o -lpthread

quantumdetect: quantumdetect.c
	gcc -g quantumdetect.c -o quantumdetect.o -lpthread

clean:
	rm -f *~ *.o *.out
