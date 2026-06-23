#!/bin/sh
set -e

REPO="gndps/sshenv"
INSTALL_DIR="/usr/local/bin"
BINARY="sshenv"

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Darwin)
        case "$ARCH" in
            arm64) TARGET="aarch64-apple-darwin" ;;
            x86_64) TARGET="x86_64-apple-darwin" ;;
            *) echo "Unsupported architecture: $ARCH" && exit 1 ;;
        esac
        ;;
    Linux)
        case "$ARCH" in
            aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
            x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
            *) echo "Unsupported architecture: $ARCH" && exit 1 ;;
        esac
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Get latest release version
echo "Fetching latest release info..."
LATEST_URL="https://api.github.com/repos/${REPO}/releases/latest"
if command -v curl >/dev/null 2>&1; then
    VERSION=$(curl -sSf "$LATEST_URL" | grep '"tag_name"' | sed 's/.*"tag_name": "\(.*\)".*/\1/')
elif command -v wget >/dev/null 2>&1; then
    VERSION=$(wget -qO- "$LATEST_URL" | grep '"tag_name"' | sed 's/.*"tag_name": "\(.*\)".*/\1/')
else
    echo "Error: curl or wget is required"
    exit 1
fi

if [ -z "$VERSION" ]; then
    echo "Error: Could not determine latest version"
    exit 1
fi

echo "Installing sshenv $VERSION for $TARGET..."

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/sshenv-${TARGET}.tar.gz"
TMP_DIR="$(mktemp -d)"
TMP_FILE="${TMP_DIR}/sshenv.tar.gz"

# Download
if command -v curl >/dev/null 2>&1; then
    curl -sSfL "$DOWNLOAD_URL" -o "$TMP_FILE"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP_FILE" "$DOWNLOAD_URL"
fi

# Extract
tar -xzf "$TMP_FILE" -C "$TMP_DIR"

# Install
if [ -w "$INSTALL_DIR" ]; then
    cp "${TMP_DIR}/sshenv" "${INSTALL_DIR}/${BINARY}"
    chmod +x "${INSTALL_DIR}/${BINARY}"
else
    echo "Installing to $INSTALL_DIR requires sudo..."
    sudo cp "${TMP_DIR}/sshenv" "${INSTALL_DIR}/${BINARY}"
    sudo chmod +x "${INSTALL_DIR}/${BINARY}"
fi

# Cleanup
rm -rf "$TMP_DIR"

echo "sshenv installed successfully to ${INSTALL_DIR}/${BINARY}"
echo "Run 'sshenv help' to get started."
