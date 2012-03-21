CC=gcc
OPTS=
LIBS=-lssl -lcrypto

all: base64.o

base64.o: base64.c
	$(CC) $(OPTS) $(LIBS) -c base64.c -o base64.o

clean:
	-rm -rf base64.o

