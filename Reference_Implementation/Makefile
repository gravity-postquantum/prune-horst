SRC=aes.c haraka.c sign.c randombytes.c

FLAGS_ALL=-std=c89 -pedantic -Wall -Wextra -Wno-long-long -march=native -lcrypto  

KERNEL_NAME := $(shell uname -s)
ifeq ($(KERNEL_NAME), Darwin)
	FLAGS_ALL += -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
endif

VERSION_S = -DLOGT=17 -DK=54 -DLOGC=6 
VERSION_M = -DLOGT=18 -DK=62 -DLOGC=7 
VERSION_L = -DLOGT=19 -DK=64 -DLOGC=7 

# CHANGE PRUNE-HORST VERSION HERE
VERSION=$(VERSION_S)

FLAGS_ALL += $(VERSION)

FLAGS_SANITIZED=$(FLAGS_ALL) -fsanitize=address,undefined -g
FLAGS_RELEASE=$(FLAGS_ALL) -O3 -fomit-frame-pointer

all: help

help:
			@echo "Please choose a target:"
			@echo "\tanalyze\t\t runs static analyzers"
			@echo "\tbench\t\t runs speed benchmarks"
			@echo "\tclean\t\t cleans up"
			@echo "\tformat\t\t formats the code using .clang-format rules"

bench:		        $(SRC) bench.c
			$(CC) $(FLAGS_RELEASE) $(VERSION_FLAGS) $^ -o bench
			./bench

format: 
			clang-format -i *.c *.h

clean:
			rm -rf bench *.dSYM *.o

analyze:
			cppcheck . --std=c89
			scan-build gcc -c $(FLAGS_SANITIZED) *.c
			cppclean .
			rm -f *.o
	
.PHONY: bench format clean
