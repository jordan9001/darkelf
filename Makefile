
CC=gcc

CFLAGS=-Wall -Werror

all: infector

infector: infector.c
	$(CC) $(CFlAGS) infector.c -o infector

tattle: tattle_payload/tattle.c
	$(CC) -c $(CFLAGS) -fpic tattle_payload/tattle.c -o tattle_payload/tattle.o
	$(CC) -shared tattle_payload/tattle.o -o tattle_payload/tattle.so

clean:
	rm -f infector
	rm -f tattle_payload/*.o tattle_payload/*.so


