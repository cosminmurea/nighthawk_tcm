CC = gcc

all: rsa
	./rsa.out

rsa:
	$(CC) -g -Wall -c -I /opt/local/include driver.c
	${CC} -g -Wall -c -I /opt/local/include rsa.c
	${CC} -g -Wall -c ../sha256/sha256.c
	${CC} -g -Wall -c ../utils/general.c
	$(CC) -o rsa.out driver.o rsa.o sha256.o general.o -L /opt/local/lib -lgmp
	rm ./*.o

.PHONY: clean

clean:
	rm rsa.out