CC=gcc
CFLAGS=-O3 -std=c99 -w -lssl -lcrypto -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
TARGET=safe
KEYGEN=safe-keygen
all: $(TARGET) $(KEYGEN)

$(TARGET): safe.c
	$(CC) safe.c $(CFLAGS) -o $(TARGET)

$(KEYGEN): ecceg_keygen.c
	$(CC) ecceg_keygen.c $(CFLAGS) -o $(KEYGEN)

clean:
	$(RM) $(TARGET) $(RM) $(KEYGEN)
