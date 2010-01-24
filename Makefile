CC=gcc
CFLAGS=-O3 -g0 -Wall -pedantic

all: speed-key


sha1.o: sha1.c sha1.h
	$(CC) $(CFLAGS) -c -o $@ $<


speed-key.o: speed-key.c sha1.h
	$(CC) $(CFLAGS) -c -o $@ $<


speed-key: speed-key.o sha1.o
	gcc  -o $@ speed-key.o sha1.o


clean:
	rm -f speed-key sha1.o key.o
