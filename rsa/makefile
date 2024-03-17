SOURCE = driver.c
TARGET = rsa.out
DEPS = ./rsa.c ../utils/general.c
CC = gcc
CFLAGS = -g -Wall

run: $(TARGET)
	./$(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) $(DEPS) -o $(TARGET)

.PHONY: clean

clean:
	rm $(TARGET)