SOURCE = driver.c
TARGET = sha256.out
DEPS = ./sha256.c ../utils/general.c
CC = gcc
CFLAGS = -g -Wall

run: $(TARGET)
	./$(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) $(DEPS) -o $(TARGET)

.PHONY: clean

clean:
	rm $(TARGET)