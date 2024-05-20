CC=gcc
STRIP=strip
CURDIR=$(PWD)
INCLUDEDIR=$(CURDIR)/include
SOURCE_DIR=$(CURDIR)/src

THIRD_PARTY_DIR=$(CURDIR)/third-party
OPENSSL_GIT=https://github.com/openssl/openssl.git
OPENSSL_BRANCH=openssl-3.3
OPENSSL_DIR=$(THIRD_PARTY_DIR)/openssl
OPENSSL_COMPILED_DIR=$(OPENSSL_DIR)/compiled
OPENSSL_COMPILED_DIR_LIB=$(OPENSSL_COMPILED_DIR)/lib64
OPENSSL_COMPILED_DIR_INCLUDE=$(OPENSSL_COMPILED_DIR)/include

FLAG=-Wall -Wno-stringop-truncation -I$(OPENSSL_COMPILED_DIR_INCLUDE) -L$(OPENSSL_COMPILED_DIR_LIB) -lcrypto -DLE
DEBUG_FLAG=-g -fsanitize=address,leak -DDEBUG $(FLAG)
TARG=nakamoto
TARG_DBG=$(TARG)_debug

NAKAMOTO_INSTALL_MSG="Nakamoto needs Openssl $(OPENSSL_BRANCH) static library installed locally. Please type \"make install_ssl\" before build \"nakamoto\""

all: main

rnd.o:
ifneq ("$(wildcard $(OPENSSL_DIR)/*)","")
	@echo "Build random object"
	@$(CC) -O2 -c $(SOURCE_DIR)/rnd.c -I$(INCLUDEDIR) -o $(SOURCE_DIR)/rnd.o $(FLAG)
else
	@echo $(NAKAMOTO_INSTALL_MSG)
endif

utility.o:
ifneq ("$(wildcard $(OPENSSL_DIR)/*)","")
	@echo "Build utility object"
	@$(CC) -O2 -c $(SOURCE_DIR)/utility.c -I$(INCLUDEDIR) -o $(SOURCE_DIR)/utility.o $(FLAG)
else
	@echo $(NAKAMOTO_INSTALL_MSG)
endif

nakamoto.o:
ifneq ("$(wildcard $(OPENSSL_DIR)/*)","")
	@echo "Build nakamoto object"
	@$(CC) -O2 -c $(SOURCE_DIR)/nakamoto.c -I$(INCLUDEDIR) -o $(SOURCE_DIR)/nakamoto.o $(FLAG)
else
	@echo $(NAKAMOTO_INSTALL_MSG)
endif

rnd_debug.o:
ifneq ("$(wildcard $(OPENSSL_DIR)/*)","")
	@echo "Build random (DEBUG) object"
	@$(CC) -O2 -c $(SOURCE_DIR)/rnd.c -I$(INCLUDEDIR) -o $(SOURCE_DIR)/rnd_debug.o $(DEBUG_FLAG)
else
	@echo $(NAKAMOTO_INSTALL_MSG)
endif

utility_debug.o:
ifneq ("$(wildcard $(OPENSSL_DIR)/*)","")
	@echo "Build utility (DEBUG) object"
	@$(CC) -O2 -c $(SOURCE_DIR)/utility.c -I$(INCLUDEDIR) -o $(SOURCE_DIR)/utility_debug.o $(DEBUG_FLAG)
else
	@echo $(NAKAMOTO_INSTALL_MSG)
endif

nakamoto_debug.o:
ifneq ("$(wildcard $(OPENSSL_DIR)/*)","")
	@echo "Build nakamoto object"
	@$(CC) -O2 -c $(SOURCE_DIR)/nakamoto.c -I$(INCLUDEDIR) -o $(SOURCE_DIR)/nakamoto_debug.o $(DEBUG_FLAG)
else
	@echo $(NAKAMOTO_INSTALL_MSG)
endif

logger_debug.o:
ifneq ("$(wildcard $(OPENSSL_DIR)/*)","")
	@echo "Build logger object"
	@$(CC) -O2 -c $(SOURCE_DIR)/logger.c -I$(INCLUDEDIR) -o $(SOURCE_DIR)/logger_debug.o $(DEBUG_FLAG)
else
	@echo $(NAKAMOTO_INSTALL_MSG)
endif

main: rnd.o utility.o nakamoto.o
ifneq ("$(wildcard $(OPENSSL_DIR)/*)","")
	@echo "Compiling $(TARG)..."
	@$(CC) -O2 -o $(TARG) main.c $(SOURCE_DIR)/utility.o $(SOURCE_DIR)/rnd.o $(SOURCE_DIR)/nakamoto.o -I$(INCLUDEDIR) $(FLAG)
	@echo "Stripping $(TARG)"
	@strip $(TARG)
	@echo "Finished"
else
	@echo $(NAKAMOTO_INSTALL_MSG)
endif

.PHONY:
clean:
ifneq ("$(wildcard $(CURDIR)/src/*.o)","")
	@echo "Removing objects ..."
	rm -v $(CURDIR)/src/*.o
else
	@echo "Nothing to do with objects"
endif

ifneq ("$(wildcard $(CURDIR)/$(TARG_DBG))","")
	@echo "Removing main $(TARG_DBG)..."
	rm -v $(CURDIR)/$(TARG_DBG)
else
	@echo "Nothing to do $(TARG_DBG)"
endif

ifneq ("$(wildcard $(CURDIR)/$(TARG))","")
	@echo "Removing main $(TARG)..."
	rm -v $(CURDIR)/$(TARG)
else
	@echo "Nothing to do $(TARG)"
endif

install_ssl:
ifeq ("$(wildcard $(OPENSSL_DIR)/*)","")
	@echo "Cloning OpenSSL $(OPENSSL_BRANCH) at $(THIRD_PARTY_DIR) ..."
	pwd; cd $(THIRD_PARTY_DIR); pwd; git clone -b $(OPENSSL_BRANCH) $(OPENSSL_GIT);cd openssl;./Configure --prefix=$(OPENSSL_COMPILED_DIR) --openssldir=$(OPENSSL_COMPILED_DIR)/ssldir;make -j12 && make -j12 test && make -j12 install;rm -rfv $(OPENSSL_COMPILED_DIR_LIB)/*.so*
	@echo "OpenSSL $(OPENSSL_BRANCH) installed successfully"
else
	@echo "OpenSSL already installed. Skipping ..."
endif

remove_ssl:
ifneq ("$(wildcard $(OPENSSL_DIR))","")
	@echo "Removing $(OPENSSL_DIR)..."
	rm -rfv $(OPENSSL_DIR)
	@echo "Done"
else
	@echo "Nothing to do: Removing SSL"
endif


debug: rnd_debug.o utility_debug.o nakamoto_debug.o logger_debug.o
ifneq ("$(wildcard $(OPENSSL_DIR)/*)","")
	@echo "Compiling $(TARG_DBG)..."
	@$(CC) -O2 -o $(TARG_DBG) main.c $(SOURCE_DIR)/utility_debug.o $(SOURCE_DIR)/rnd_debug.o $(SOURCE_DIR)/nakamoto_debug.o $(SOURCE_DIR)/logger_debug.o -I$(INCLUDEDIR) $(DEBUG_FLAG)
	@echo "Finished"
else
	@echo $(NAKAMOTO_INSTALL_MSG)
endif

