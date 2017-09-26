BIN=nist_kats
KATFILES=PQCsignKAT_64.rsp PQCsignKAT_64.req
SRCPATH=../Additional_Implementations/fast/

CFLAGS=-O2 -march=native -Wall -Wextra -pedantic -std=c99
LDFLAGS=-lcrypto

KERNEL_NAME := $(shell uname -s)
ifeq ($(KERNEL_NAME), Darwin)
	CFLAGS += -I/usr/local/opt/openssl/include
	LDFLAGS += -L/usr/local/opt/openssl/lib
endif

VERSION_S = -DLOGT=17 -DK=54 -DLOGC=6 -DCRYPTO_PUBLICKEYBYTES=2048 -DCRYPTO_BYTES=20768
VERSION_M = -DLOGT=18 -DK=62 -DLOGC=7 -DCRYPTO_PUBLICKEYBYTES=4096 -DCRYPTO_BYTES=23840
VERSION_L = -DLOGT=19 -DK=64 -DLOGC=7 -DCRYPTO_PUBLICKEYBYTES=4096 -DCRYPTO_BYTES=26656

VERSION=$(VERSION_S)

CFLAGS += $(VERSION) -DCRYPTO_SECRETKEYBYTES=64 
CFLAGS += -I$(SRCPATH)

all: $(BIN)

$(BIN): PQCgenKAT_sign.c rng.c $(SRCPATH)aes.c $(SRCPATH)haraka.c $(SRCPATH)sign.c
	$(CC) $(CFLAGS) -o $@ $? $(LDFLAGS)
	./$(BIN)

clean:
	rm -rf $(KATFILES) $(BIN)

.PHONY: all $(BIN)
