CC=gcc
STRIP=strip
CURDIR=$(PWD)
INCLUDEDIR=$(CURDIR)/include
SOURCE_DIR=$(CURDIR)/src
FLAG=-Wall -Wno-stringop-truncation -I$(CURDIR)/compiled/include -L$(CURDIR)/compiled/lib64 -lcrypto -DLE
DEBUG_FLAG=-g -fsanitize=address,leak -DDEBUG $(FLAG)
TARG=nakamoto
TARG_DBG=$(TARG)_debug

all: main

rnd.o:
	@echo "Build random object"
	@$(CC) -O2 -c $(SOURCE_DIR)/rnd.c -I$(INCLUDEDIR) -o $(SOURCE_DIR)/rnd.o $(FLAG)

utility.o:
	@echo "Build utility object"
	@$(CC) -O2 -c $(SOURCE_DIR)/utility.c -I$(INCLUDEDIR) -o $(SOURCE_DIR)/utility.o $(FLAG)

nakamoto.o:
	@echo "Build nakamoto object"
	@$(CC) -O2 -c $(SOURCE_DIR)/nakamoto.c -I$(INCLUDEDIR) -o $(SOURCE_DIR)/nakamoto.o $(FLAG)

rnd_debug.o:
	@echo "Build random (DEBUG) object"
	@$(CC) -O2 -c $(SOURCE_DIR)/rnd.c -I$(INCLUDEDIR) -o $(SOURCE_DIR)/rnd_debug.o $(DEBUG_FLAG)

utility_debug.o:
	@echo "Build utility (DEBUG) object"
	@$(CC) -O2 -c $(SOURCE_DIR)/utility.c -I$(INCLUDEDIR) -o $(SOURCE_DIR)/utility_debug.o $(DEBUG_FLAG)

nakamoto_debug.o:
	@echo "Build nakamoto object"
	@$(CC) -O2 -c $(SOURCE_DIR)/nakamoto.c -I$(INCLUDEDIR) -o $(SOURCE_DIR)/nakamoto_debug.o $(DEBUG_FLAG)

logger_debug.o:
	@echo "Build logger object"
	@$(CC) -O2 -c $(SOURCE_DIR)/logger.c -I$(INCLUDEDIR) -o $(SOURCE_DIR)/logger_debug.o $(DEBUG_FLAG)

main: rnd.o utility.o nakamoto.o
	@echo "Compiling $(TARG)..."
	@$(CC) -O2 -o $(TARG) main.c $(SOURCE_DIR)/utility.o $(SOURCE_DIR)/rnd.o $(SOURCE_DIR)/nakamoto.o -I$(INCLUDEDIR) $(FLAG)
	@echo "Stripping $(TARG)"
	@strip $(TARG)
	@echo "Finished"

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

.PHONY:
debug: rnd_debug.o utility_debug.o nakamoto_debug.o logger_debug.o
	@echo "Compiling $(TARG_DBG)..."
	@$(CC) -O2 -o $(TARG_DBG) main.c $(SOURCE_DIR)/utility_debug.o $(SOURCE_DIR)/rnd_debug.o $(SOURCE_DIR)/nakamoto_debug.o $(SOURCE_DIR)/logger_debug.o -I$(INCLUDEDIR) $(DEBUG_FLAG)
	@echo "Finished"

