CC = gcc
CFLAGS = -g -Wall
SOURCE = driver.c
DEPS = ./aes.c ../utils/general.c ../utils/pkcs7.c
TARGET = aes.out

run: $(TARGET)
	./$(TARGET)

$(TARGET): $(SOURCE) $(DEPS)
	$(CC) $(CFLAGS) $(SOURCE) $(DEPS) -o $(TARGET)

.PHONY: clean

clean:
	rm $(TARGET)