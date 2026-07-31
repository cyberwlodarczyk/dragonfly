CC=gcc
CFLAGS= \
	-Wall \
	-Wextra \
	-Werror=unused-result \
	-Wpedantic \
	-Werror \
	-Wmissing-prototypes \
	-Wshadow \
	-Wpointer-arith \
	-Wredundant-decls \
	-Wconversion \
	-Wsign-conversion \
	-Wno-long-long \
	-Wno-unknown-pragmas \
	-Wno-unused-command-line-argument \
	-O3 \
	-fomit-frame-pointer \
	-std=c99 \
	-pedantic \
	-MMD

SRC_DIR=src
BUILD_DIR=build
BIN_DIR=bin
BIN_MAIN=$(BIN_DIR)/main

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(@D)
	$(CC) -c $(CFLAGS) -Isrc $^ -o $@

$(BIN_DIR)/%: %.c $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(wildcard $(SRC_DIR)/*.c))
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -I. $^ -o $@ -lcrypto

build: $(BIN_MAIN)

run: $(BIN_MAIN)
	./$(BIN_MAIN)

clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(BIN_DIR)
