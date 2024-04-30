CC = gcc
CFLAGS = -g -Wall
OBJECTS = driver.o rsa.o sha256.o general.o
TARGET = rsa.out

all: rsa
	./$(TARGET)

rsa:
	$(CC) $(CFLAGS) -c -I /opt/local/include driver.c
	${CC} $(CFLAGS) -c -I /opt/local/include rsa.c
	${CC} $(CFLAGS) -c ../sha256/sha256.c
	${CC} $(CFLAGS) -c ../utils/general.c
	$(CC) -o $(TARGET) $(OBJECTS) -L /opt/local/lib -lgmp

.PHONY: clean

clean:
	rm $(OBJECTS)
	rm $(TARGET)