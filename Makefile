# OpenSSL Keyring Provider Makefile

# Build configuration
CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2 -Wstrict-prototypes \
         -Wmissing-prototypes -Wcast-qual -Wcast-align -Wwrite-strings -Wundef \
         -Wredundant-decls -Wnull-dereference -Wdouble-promotion -Wformat-security \
         -fPIC -O2 -g
LDFLAGS = -shared
VERSION_SCRIPT = libkeyring.map

# Package configuration
OPENSSL_CFLAGS = $(shell pkg-config --cflags libcrypto)
OPENSSL_LIBS = $(shell pkg-config --libs libcrypto)
KEYUTILS_LIBS = -lkeyutils
TROUSERS_LIBS = -ltspi

# Directories
SRC_DIR = src
INC_DIR = include
TEST_DIR = tests
TOOLS_DIR = tools
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj
LIB_DIR = $(BUILD_DIR)/lib
BIN_DIR = $(BUILD_DIR)/bin

# Provider library
PROVIDER_NAME = keyring
PROVIDER_LIB = $(LIB_DIR)/$(PROVIDER_NAME).so

# Source files
PROVIDER_SRCS = $(SRC_DIR)/provider.c \
                $(SRC_DIR)/keyring_uri.c \
                $(SRC_DIR)/keyring_loader.c \
                $(SRC_DIR)/keyring_rsa.c \
                $(SRC_DIR)/keyring_signature.c \
                $(SRC_DIR)/keyring_asym_cipher.c \
                $(SRC_DIR)/keyring_store.c \
                $(SRC_DIR)/keyring_pkey.c \
                $(SRC_DIR)/keyring_self_test.c \
                $(SRC_DIR)/util.c

PROVIDER_OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(PROVIDER_SRCS))

# Test sources
TEST_SRCS = $(wildcard $(TEST_DIR)/*.c)
TEST_BINS = $(patsubst $(TEST_DIR)/%.c,$(BIN_DIR)/%,$(TEST_SRCS))

# Phony targets
.PHONY: all clean install uninstall test help

# Default target
all: $(PROVIDER_LIB) tests

# Create directories
$(OBJ_DIR) $(LIB_DIR) $(BIN_DIR):
	mkdir -p $@

# Provider library
$(PROVIDER_LIB): $(PROVIDER_OBJS) | $(LIB_DIR)
	$(CC) $(LDFLAGS) -Wl,--version-script=$(VERSION_SCRIPT) -o $@ $^ $(OPENSSL_LIBS) $(KEYUTILS_LIBS)

# Compile provider objects
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -I$(INC_DIR) -c -o $@ $<

# Build tests
# Note: Tests are built by compiling directly with provider sources,
# not by linking to the shared library (which only exports OSSL_provider_init)
tests: $(TEST_BINS)

$(BIN_DIR)/test_%: $(TEST_DIR)/test_%.c $(PROVIDER_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -I$(INC_DIR) -o $@ $< $(PROVIDER_OBJS) \
		$(OPENSSL_LIBS) $(KEYUTILS_LIBS)

# Run tests
test: tests
	@echo "Running test suite..."
	@for test in $(TEST_BINS); do \
		echo "Running $$test..."; \
		OPENSSL_MODULES=$(LIB_DIR) $$test || exit 1; \
	done
	@echo "All tests passed!"

# Install provider
OPENSSL_MODULESDIR = $(shell pkg-config --variable=modulesdir libcrypto)
ifeq ($(OPENSSL_MODULESDIR),)
OPENSSL_MODULESDIR = /usr/lib/x86_64-linux-gnu/ossl-modules
endif

install: $(PROVIDER_LIB)
	install -d $(DESTDIR)$(OPENSSL_MODULESDIR)
	install -m 755 $(PROVIDER_LIB) $(DESTDIR)$(OPENSSL_MODULESDIR)/

uninstall:
	rm -f $(DESTDIR)$(OPENSSL_MODULESDIR)/$(PROVIDER_NAME).so

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Help
help:
	@echo "OpenSSL Keyring Provider - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build provider library and tests (default)"
	@echo "  tests      - Build test suite"
	@echo "  test       - Run test suite"
	@echo "  install    - Install provider"
	@echo "  uninstall  - Remove installed files"
	@echo "  clean      - Remove build artifacts"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Environment:"
	@echo "  OPENSSL_MODULESDIR = $(OPENSSL_MODULESDIR)"
	@echo "  CC = $(CC)"
	@echo "  CFLAGS = $(CFLAGS)"
