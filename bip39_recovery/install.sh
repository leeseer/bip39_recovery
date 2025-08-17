#!/bin/bash

# BIP39 Recovery Tool Installer
# This script installs the BIP39 Recovery Tool and its dependencies

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print functions
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on supported OS
check_os() {
    print_info "Checking operating system..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        print_info "Detected Linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        print_info "Detected macOS"
    else
        print_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
}

# Install Rust and Cargo
install_rust() {
    print_info "Checking for Rust and Cargo..."
    
    if command -v cargo &> /dev/null; then
        print_info "Rust and Cargo are already installed"
        return
    fi
    
    print_info "Installing Rust and Cargo..."
    
    if [[ "$OS" == "linux" ]]; then
        # Check for package manager
        if command -v apt &> /dev/null; then
            sudo apt update
            sudo apt install -y curl build-essential
        elif command -v yum &> /dev/null; then
            sudo yum install -y curl gcc gcc-c++ make
        elif command -v pacman &> /dev/null; then
            sudo pacman -S curl base-devel
        else
            print_error "Unsupported package manager. Please install curl and build tools manually."
            exit 1
        fi
    elif [[ "$OS" == "macos" ]]; then
        # Check if Homebrew is installed
        if ! command -v brew &> /dev/null; then
            print_info "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
    fi
    
    # Install Rust
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    
    # Source cargo environment
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi
    
    # Add cargo to PATH for current session
    export PATH="$HOME/.cargo/bin:$PATH"
    
    # Verify installation
    if ! command -v cargo &> /dev/null; then
        print_error "Failed to install Cargo. Please install Rust manually."
        exit 1
    fi
    
    print_info "Rust and Cargo installed successfully"
}

# Install CUDA (optional)
install_cuda() {
    print_info "Checking for CUDA support..."
    
    # Check if user wants CUDA support
    read -p "Do you want to install CUDA support for GPU acceleration? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Skipping CUDA installation"
        return
    fi
    
    if [[ "$OS" == "linux" ]]; then
        # Check for NVIDIA GPU
        if ! command -v nvidia-smi &> /dev/null; then
            print_warn "NVIDIA GPU not detected. CUDA may not work properly."
        fi
        
        # Try to install CUDA
        if command -v apt &> /dev/null; then
            print_info "Installing CUDA toolkit..."
            sudo apt update
            sudo apt install -y nvidia-cuda-toolkit
        elif command -v yum &> /dev/null; then
            sudo yum install -y cuda
        else
            print_warn "Please install CUDA toolkit manually from https://developer.nvidia.com/cuda-downloads"
        fi
    elif [[ "$OS" == "macos" ]]; then
        print_warn "CUDA is not supported on macOS. GPU acceleration will not be available."
    fi
}

# Clone and build the project
install_bip39_recovery() {
    print_info "Installing BIP39 Recovery Tool..."
    
    # Create installation directory
    INSTALL_DIR="$HOME/.bip39_recovery"
    print_info "Creating installation directory: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    
    # Clone the repository
    if [ -d "$INSTALL_DIR/bip39_recovery" ]; then
        print_info "Updating existing repository..."
        cd "$INSTALL_DIR/bip39_recovery"
        git pull
    else
        print_info "Cloning repository..."
        git clone https://github.com/your-username/bip39_recovery.git "$INSTALL_DIR/bip39_recovery"
        cd "$INSTALL_DIR/bip39_recovery"
    fi
    
    # Build the project
    print_info "Building BIP39 Recovery Tool..."
    
    # Check if CUDA support is available
    if command -v nvcc &> /dev/null; then
        print_info "Building with CUDA support..."
        cargo build --release --features cuda
        BUILD_FEATURES="cuda"
    else
        print_info "Building without CUDA support..."
        cargo build --release
        BUILD_FEATURES=""
    fi
    
    # Create symlink for easy access
    print_info "Creating symlink..."
    sudo ln -sf "$INSTALL_DIR/bip39_recovery/target/release/bip39_recovery" /usr/local/bin/bip39_recovery
    
    print_info "BIP39 Recovery Tool installed successfully!"
}

# Create desktop entry (Linux only)
create_desktop_entry() {
    if [[ "$OS" != "linux" ]]; then
        return
    fi
    
    print_info "Creating desktop entry..."
    
    DESKTOP_ENTRY="[Desktop Entry]
Name=BIP39 Recovery Tool
Comment=Recover BIP39 mnemonics by brute-forcing missing words
Exec=$INSTALL_DIR/bip39_recovery/target/release/bip39_recovery
Icon=application-x-executable
Terminal=true
Type=Application
Categories=Utility;Security;
"
    
    mkdir -p "$HOME/.local/share/applications"
    echo "$DESKTOP_ENTRY" > "$HOME/.local/share/applications/bip39_recovery.desktop"
    
    print_info "Desktop entry created"
}

# Main installation function
main() {
    print_info "Starting BIP39 Recovery Tool installation..."
    
    check_os
    install_rust
    install_cuda
    install_bip39_recovery
    create_desktop_entry
    
    print_info "Installation completed successfully!"
    echo
    print_info "You can now run the tool with:"
    echo "  bip39_recovery --help"
    echo
    print_info "For more information, see the README.md file in the installation directory:"
    echo "  $INSTALL_DIR/bip39_recovery/README.md"
}

# Run main function
main "$@"