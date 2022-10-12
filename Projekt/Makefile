CC=g++
CFLAGS=-I.

all: netflow

netflow: netflow.o
	$(CC) -o netflow netflow.o -lpcap

clean:
	rm *.o netflow
