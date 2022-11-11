CC=g++
CFLAGS=-I.
FILES= flow.cpp arguments.cpp netflow_generator.cpp

all: flow

flow: $(FILES)
	$(CC) $(CFLAGS) -o flow $(FILES) -lpcap

clean:
	rm *.o flow
