SOURCE = driver.c
TARGET = entropy.out
DEPS = ./entropy.c ../utils/general.c ../sha256/sha256.c
CC = gcc
CFLAGS = -g -Wall

run: $(TARGET)
	./$(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) $(DEPS) -o $(TARGET)

.PHONY: clean

clean:
	rm $(TARGET)