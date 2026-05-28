#!/bin/bash
# =============================================================================
# Sentinella — Auto-Install Deployment & Bootstrap Script
# =============================================================================
# This script ensures that all system-level dependencies for the Tauri interface
# are present on the host Debian/Kali machine, installs them if missing,
# and starts the compiled eBPF-enabled desktop binary with necessary privileges.
# =============================================================================

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo -e "\e[1;31m[ERROR] This script must be run as root (using sudo).\e[0m" >&2
    echo -e "Usage: sudo ./install.sh" >&2
    exit 1
fi

echo -e "\e[1;34m[INFO] Starting Sentinella installation check...\e[0m"

# Define required dependencies
DEPENDENCIES=("libwebkit2gtk-4.1-dev" "curl" "wget")
MISSING_DEPS=()

# Silently check for required Debian/Kali dependencies
for dep in "${DEPENDENCIES[@]}"; do
    if ! dpkg-query -W -f='${Status}' "$dep" 2>/dev/null | grep -q "ok installed"; then
        MISSING_DEPS+=("$dep")
    fi
done

# If there are missing dependencies, automatically install them
if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
    echo -e "\e[1;33m[WARN] Missing system dependencies: ${MISSING_DEPS[*]}\e[0m"
    echo -e "\e[1;34m[INFO] Updating apt package indices...\e[0m"
    apt-get update -y >/dev/null 2>&1
    
    echo -e "\e[1;34m[INFO] Installing missing packages silently...\e[0m"
    if apt-get install -y "${MISSING_DEPS[@]}" >/dev/null 2>&1; then
        echo -e "\e[1;32m[SUCCESS] Installed missing dependencies successfully.\e[0m"
    else
        echo -e "\e[1;31m[ERROR] Failed to install missing dependencies automatically.\e[0m" >&2
        exit 1
    fi
else
    echo -e "\e[1;32m[SUCCESS] All required system dependencies are already installed.\e[0m"
fi

# Locate the compiled Sentinella release binary
BINARY_PATH="./target/release/sentinella"
if [ ! -f "$BINARY_PATH" ]; then
    # Fallback to standard cargo workspace target build name if product name build is missing
    BINARY_PATH="./target/release/sentinella-tauri"
fi

if [ ! -f "$BINARY_PATH" ]; then
    echo -e "\e[1;31m[ERROR] Compiled Sentinella release binary not found at $BINARY_PATH.\e[0m" >&2
    echo -e "Please compile Sentinella in release mode first by running:" >&2
    echo -e "  cargo build --release" >&2
    exit 1
fi

echo -e "\e[1;32m[SUCCESS] Found binary at $BINARY_PATH. Launching Sentinella...\e[0m"

# Execute the binary
exec "$BINARY_PATH"
