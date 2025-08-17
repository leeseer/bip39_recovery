# Makefile for BIP39 Recovery Tool

# Variables
CARGO = cargo
TARGET_DIR = target/release
BINARY = bip39_recovery
INSTALL_DIR = /usr/local/bin

# Default target
.PHONY: all
all: build

# Build the project
.PHONY: build
build:
	$(CARGO) build --release

# Build with CUDA support
.PHONY: build-cuda
build-cuda:
	$(CARGO) build --release --features cuda

# Install the binary
.PHONY: install
install: build
	sudo cp $(TARGET_DIR)/$(BINARY) $(INSTALL_DIR)/$(BINARY)

# Install with CUDA support
.PHONY: install-cuda
install-cuda: build-cuda
	sudo cp $(TARGET_DIR)/$(BINARY) $(INSTALL_DIR)/$(BINARY)

# Clean build artifacts
.PHONY: clean
clean:
	$(CARGO) clean

# Run tests
.PHONY: test
test:
	$(CARGO) test

# Format the code
.PHONY: fmt
fmt:
	$(CARGO) fmt

# Check for linting issues
.PHONY: check
check:
	$(CARGO) check

# Check with CUDA support
.PHONY: check-cuda
check-cuda:
	$(CARGO) check --features cuda

# Help
.PHONY: help
help:
	@echo "BIP39 Recovery Tool Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make              Build the project"
	@echo "  make build        Build the project"
	@echo "  make build-cuda   Build with CUDA support"
	@echo "  make install      Install the binary"
	@echo "  make install-cuda Install with CUDA support"
	@echo "  make clean        Clean build artifacts"
	@echo "  make test         Run tests"
	@echo "  make fmt          Format the code"
	@echo "  make check        Check for linting issues"
	@echo "  make check-cuda   Check with CUDA support"
	@echo "  make help         Show this help message"