# Adrian's Makefile for CSE 508 project 3

all: clean quantuminject quantumdetect myping

quantuminject: quantuminject.c
	gcc -g quantuminject.c -lpcap -o quantuminject.o

quantumdetect: quantumdetect.c
	gcc -g quantumdetect.c -lpcap -o quantumdetect.o

myping: myping.c
	gcc -g myping.c -o myping.o

clean:
	rm -f *~ *.o *.out
