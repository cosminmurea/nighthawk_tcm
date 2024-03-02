SOURCE = driver.c
TARGET = sha256.out
DEPS = ./utils.c ./sha256.c
CC = gcc
CFLAGS = -g -Wall

run: $(TARGET)
	./$(TARGET) $(FILE)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) $(DEPS) -o $(TARGET)

.PHONY: clean

clean:
	rm $(TARGET)