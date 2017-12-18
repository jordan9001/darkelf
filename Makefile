
CC=gcc

all: infector testso testfile

infector: infector.c
	$(CC) -Wall -Werror -g infector.c stager.S -o infector

testso:
	$(CC) -Wall -g -fPIC -shared ./testing/testso.c -o ./testing/testso.so

testfile:
	$(CC) -Wall -g ./testing/testfile.c -o ./testing/testfile

clean:
	rm -f infector
	rm -f ./testing/testso.so
	rm -f ./testing/testfile
	rm -f ./testing/testfile_infected	
