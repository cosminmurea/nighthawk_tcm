SOURCE = driver.c
TARGET = entropy.out
DEPS = ./entropy.c
CC = gcc
CFLAGS = -g -Wall

run: $(TARGET)
	./$(TARGET) $(FILE)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) $(DEPS) -o $(TARGET)

.PHONY: clean

clean:
	rm $(TARGET)