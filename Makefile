# OpenSSL Keyring Provider Makefile

# Build configuration
CC = gcc
CFLAGS = -Wall -Wextra -fPIC -O2 -g
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
PROVIDER_LIB = $(LIB_DIR)/lib$(PROVIDER_NAME).so
PROVIDER_MODULE = $(LIB_DIR)/$(PROVIDER_NAME).so

# Source files
PROVIDER_SRCS = $(SRC_DIR)/provider.c \
                $(SRC_DIR)/keyring_uri.c \
                $(SRC_DIR)/keyring_loader.c \
                $(SRC_DIR)/keyring_rsa.c \
                $(SRC_DIR)/keyring_signature.c \
                $(SRC_DIR)/keyring_asym_cipher.c \
                $(SRC_DIR)/keyring_tpm.c \
                $(SRC_DIR)/util.c

PROVIDER_OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(PROVIDER_SRCS))

# Tool sources
TOOL_SRCS = $(wildcard $(TOOLS_DIR)/*.c)
TOOL_BINS = $(patsubst $(TOOLS_DIR)/%.c,$(BIN_DIR)/%,$(TOOL_SRCS))

# Test sources
TEST_SRCS = $(wildcard $(TEST_DIR)/*.c)
TEST_BINS = $(patsubst $(TEST_DIR)/%.c,$(BIN_DIR)/%,$(TEST_SRCS))

# Phony targets
.PHONY: all clean install uninstall test tools help

# Default target
all: $(PROVIDER_LIB) tools tests

# Create directories
$(OBJ_DIR) $(LIB_DIR) $(BIN_DIR):
	mkdir -p $@

# Provider library
$(PROVIDER_LIB): $(PROVIDER_OBJS) | $(LIB_DIR)
	$(CC) $(LDFLAGS) -Wl,--version-script=$(VERSION_SCRIPT) -o $@ $^ $(OPENSSL_LIBS) $(KEYUTILS_LIBS)
	ln -sf lib$(PROVIDER_NAME).so $(PROVIDER_MODULE)

# Compile provider objects
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -I$(INC_DIR) -c -o $@ $<

# Build tools
# Note: Tools are built by compiling directly with provider sources,
# not by linking to the shared library (which only exports OSSL_provider_init)
tools: $(TOOL_BINS)

# keyattest needs TrouSerS for TPM attestation operations
$(BIN_DIR)/keyattest: $(TOOLS_DIR)/keyattest.c $(PROVIDER_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -I$(INC_DIR) -o $@ $< $(PROVIDER_OBJS) \
		$(OPENSSL_LIBS) $(KEYUTILS_LIBS) $(TROUSERS_LIBS)

# Other tools don't need TrouSerS
$(BIN_DIR)/%: $(TOOLS_DIR)/%.c $(PROVIDER_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -I$(INC_DIR) -o $@ $< $(PROVIDER_OBJS) \
		$(OPENSSL_LIBS) $(KEYUTILS_LIBS)

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

install: $(PROVIDER_LIB) tools
	install -d $(DESTDIR)$(OPENSSL_MODULESDIR)
	install -m 755 $(PROVIDER_LIB) $(DESTDIR)$(OPENSSL_MODULESDIR)/
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(TOOL_BINS) $(DESTDIR)/usr/local/bin/

uninstall:
	rm -f $(DESTDIR)$(OPENSSL_MODULESDIR)/lib$(PROVIDER_NAME).so
	rm -f $(DESTDIR)/usr/local/bin/keygen
	rm -f $(DESTDIR)/usr/local/bin/keyimport
	rm -f $(DESTDIR)/usr/local/bin/keyattest
	rm -f $(DESTDIR)/usr/local/bin/keyinfo

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Help
help:
	@echo "OpenSSL Keyring Provider - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build provider library, tools, and tests (default)"
	@echo "  tools      - Build key management tools"
	@echo "  tests      - Build test suite"
	@echo "  test       - Run test suite"
	@echo "  install    - Install provider and tools"
	@echo "  uninstall  - Remove installed files"
	@echo "  clean      - Remove build artifacts"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Environment:"
	@echo "  OPENSSL_MODULESDIR = $(OPENSSL_MODULESDIR)"
	@echo "  CC = $(CC)"
	@echo "  CFLAGS = $(CFLAGS)"
