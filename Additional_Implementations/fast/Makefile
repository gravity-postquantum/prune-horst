SRC=aes.c haraka.c sign.c
BINS=gen_ivs_* bench
IVSFILE=IntermediateValues.txt

FLAGS_ALL=-std=c89 -pedantic -Wall -Wextra -Wno-long-long -march=native -lcrypto  

KERNEL_NAME := $(shell uname -s)
ifeq ($(KERNEL_NAME), Darwin)
	FLAGS_ALL += -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
endif

VERSION_S = -DLOGT=17 -DK=54 -DLOGC=6 
VERSION_M = -DLOGT=18 -DK=62 -DLOGC=7 
VERSION_L = -DLOGT=19 -DK=64 -DLOGC=7 

VERSION=$(VERSION_S)

FLAGS_ALL += $(VERSION)

FLAGS_SANITIZED=$(FLAGS_ALL) -fsanitize=address,undefined -g
FLAGS_RELEASE=$(FLAGS_ALL) -O3 -fomit-frame-pointer

all: help

help:
			@echo "Please choose a target:"
			@echo "\tivs\t\t generates intermediate values using the fast code"
			@echo "\tcheck\t\t verifies intermediate values using the fast code"
			@echo "\tcheckref\t verifies intermediate values using the reference code"
			@echo "\tbench\t\t runs speed benchmarks"
			@echo "\tanalyze\t\t runs static analyzers"
			@echo "\tformat\t\t formats the code using .clang-format rules"
			@echo "\tcloc\t\t counts lines of code"
			@echo "\tclean\t\t cleans up, except intermediate values file"

check:		$(SRC) gen_ivs.c $(IVSFILE)
			@$(CC) $(FLAGS_RELEASE) $(VERSION_FLAGS) -DDEBUG $(SRC) gen_ivs.c -o gen_ivs_release
			@./gen_ivs_release > $(IVSFILE)_tmp
			@diff $(IVSFILE) $(IVSFILE)_tmp ; if [ $$? -ne 0 ] ; then echo "error" ; else echo "ok" ; fi
			@rm -f $(IVSFILE)_tmp

checkref:	$(SRC) gen_ivs.c $(IVSFILE)
			@$(CC) $(FLAGS_RELEASE) $(VERSION_FLAGS) -DDEBUG $(SRC) gen_ivs.c -o gen_ivs_release -DREFERENCE
			@./gen_ivs_release > $(IVSFILE)_tmp
			@diff $(IVSFILE) $(IVSFILE)_tmp ; if [ $$? -ne 0 ] ; then echo "error" ; else echo "ok" ; fi
			@rm -f $(IVSFILE)_tmp

ivs:		$(SRC) gen_ivs.c
			$(CC) $(FLAGS_RELEASE) $(VERSION_FLAGS) -DDEBUG $^ -o gen_ivs_release
			./gen_ivs_release > $(IVSFILE)_tmp
			./gen_ivs_release > $(IVSFILE)
			@diff $(IVSFILE) $(IVSFILE)_tmp ; if [ $$? -ne 0 ] ; then echo "error: IVS differ" ;fi

			$(CC) $(FLAGS_SANITIZED) $(VERSION_FLAGS) -DDEBUG $^ -o gen_ivs_sanitized
			./gen_ivs_sanitized > $(IVSFILE)_tmp
			@diff $(IVSFILE) $(IVSFILE)_tmp ; if [ $$? -ne 0 ] ; then echo "error: IVS differ" ;fi

			@rm -f $(IVSFILE)_tmp

bench:		$(SRC) bench.c
			$(CC) $(FLAGS_RELEASE) $(VERSION_FLAGS) $^ -o bench
			./bench

format: 
			clang-format -i *.c *.h

clean:
			rm -rf $(BINS) *.dSYM

cleanall:	clean
			rm -rf $(IVSFILE)

analyze:
			cppcheck . --std=c89
			scan-build gcc -c $(FLAGS_ALL) $(VERSION_FLAGS) *.c
			cppclean .
			rm -f *.o

cloc:		
			cloc $(wildcard *.c) $(wildcard *.h)
	
.PHONY: bench format clean checks cloc
