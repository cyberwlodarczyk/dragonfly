CC = gcc
CFLAGS := \
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
	-march=native \
	-fomit-frame-pointer \
	-std=c99 \
	-pedantic \
	-MMD \
	$(CFLAGS)

SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin
BIN_TEST = $(BIN_DIR)/test
BIN_PERF = $(BIN_DIR)/perf

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(@D)
	$(CC) -c $(CFLAGS) -Isrc $^ -o $@

$(BIN_DIR)/%: %.c shared.c $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(wildcard $(SRC_DIR)/*.c))
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -I. $^ -o $@ -lcrypto

build: $(BIN_TEST) $(BIN_PERF)

test: $(BIN_TEST)
	./$(BIN_TEST)

perf: $(BIN_PERF)
	./$(BIN_PERF)

clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(BIN_DIR)
