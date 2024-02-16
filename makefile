CC = gcc
CFLAGS = -g -Wall
SOURCE = driver.c
DEPS = aes.c
TARGET = aes

run: $(TARGET)
	./$(TARGET)

$(TARGET): $(SOURCE) $(DEPS)
	$(CC) $(CFLAGS) $(SOURCE) $(DEPS) -o $(TARGET)

.PHONY: clean

clean:
	rm $(TARGET)