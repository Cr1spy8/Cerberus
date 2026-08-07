#!/usr/bin/env bash

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER_DIR="$HOME/bin"
LAUNCHER_PATH="$LAUNCHER_DIR/cerberus"

CONFIG_DIR="$PROJECT_DIR/config"
CONFIG_FILE="$CONFIG_DIR/cerberus.json"
CONFIG_TEMPLATE="$CONFIG_DIR/cerberus.example.json"

RUNTIME_DIRS=(
    "$PROJECT_DIR/inventory"
    "$PROJECT_DIR/scans"
    "$PROJECT_DIR/reports"
    "$PROJECT_DIR/logs"
)

echo "=============================================================="
echo "                      CERBERUS INSTALLER"
echo "              Portable Penetration Testing Appliance"
echo "=============================================================="
echo

echo "[*] Project directory:"
echo "    $PROJECT_DIR"
echo

# ------------------------------------------------------------
# Dependency checks
# ------------------------------------------------------------

echo "[*] Checking dependencies..."

if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] Python 3 was not found."
    echo "    Install it before continuing."
    exit 1
fi

PYTHON_VERSION="$(python3 --version 2>&1)"
echo "[+] Python: $PYTHON_VERSION"

if ! command -v nmap >/dev/null 2>&1; then
    echo "[!] Nmap was not found."
    echo "    Install with:"
    echo "    sudo apt install nmap"
    exit 1
fi

NMAP_VERSION="$(nmap --version | head -n 1)"
echo "[+] Nmap:   $NMAP_VERSION"

if ! command -v ip >/dev/null 2>&1; then
    echo "[!] The 'ip' networking command was not found."
    echo "    Install the iproute2 package before continuing."
    exit 1
fi

echo "[+] Network tools available."
echo

# ------------------------------------------------------------
# Runtime directories
# ------------------------------------------------------------

echo "[*] Preparing runtime directories..."

for directory in "${RUNTIME_DIRS[@]}"; do
    mkdir -p "$directory"
    echo "[+] $directory"
done

mkdir -p "$CONFIG_DIR"
echo

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

echo "[*] Checking configuration..."

if [[ ! -f "$CONFIG_FILE" ]]; then
    if [[ -f "$CONFIG_TEMPLATE" ]]; then
        cp "$CONFIG_TEMPLATE" "$CONFIG_FILE"

        chmod 600 "$CONFIG_FILE"

        echo "[+] Created local configuration:"
        echo "    $CONFIG_FILE"
    else
        echo "[!] Configuration template not found:"
        echo "    $CONFIG_TEMPLATE"
        exit 1
    fi
else
    chmod 600 "$CONFIG_FILE"

    echo "[+] Existing configuration preserved:"
    echo "    $CONFIG_FILE"
fi

echo

# ------------------------------------------------------------
# Python validation
# ------------------------------------------------------------

echo "[*] Validating Cerberus Python source..."

if python3 -m compileall -q "$PROJECT_DIR/cerberus"; then
    echo "[+] Cerberus source compilation passed."
else
    echo "[!] Cerberus source compilation failed."
    exit 1
fi

echo

# ------------------------------------------------------------
# Launcher
# ------------------------------------------------------------

echo "[*] Installing Cerberus launcher..."

mkdir -p "$LAUNCHER_DIR"

cat > "$LAUNCHER_PATH" <<EOF
#!/usr/bin/env bash

set -e

PROJECT_DIR="$PROJECT_DIR"

cd "\$PROJECT_DIR" || exit 1
exec python3 -m cerberus.cli "\$@"
EOF

chmod +x "$LAUNCHER_PATH"

echo "[+] Launcher installed:"
echo "    $LAUNCHER_PATH"
echo

# ------------------------------------------------------------
# PATH configuration
# ------------------------------------------------------------

if [[ ":$PATH:" != *":$LAUNCHER_DIR:"* ]]; then

    if [[ -n "${ZSH_VERSION:-}" || "${SHELL:-}" == *"zsh"* ]]; then
        SHELL_CONFIG="$HOME/.zshrc"
    else
        SHELL_CONFIG="$HOME/.bashrc"
    fi

    touch "$SHELL_CONFIG"

    PATH_LINE='export PATH="$HOME/bin:$PATH"'

    if ! grep -Fqx "$PATH_LINE" "$SHELL_CONFIG"; then
        echo "$PATH_LINE" >> "$SHELL_CONFIG"
    fi

    echo "[*] Added ~/bin to PATH in:"
    echo "    $SHELL_CONFIG"
    echo
    echo "[i] Restart the terminal or run:"
    echo "    source $SHELL_CONFIG"
    echo
else
    echo "[+] ~/bin is already available in PATH."
    echo
fi

# ------------------------------------------------------------
# Security reminder
# ------------------------------------------------------------

if [[ -n "${CERBERUS_HEC_TOKEN:-}" ]]; then
    echo "[+] Splunk HEC token detected in current environment."
else
    echo "[i] Splunk HEC token is not currently configured."
    echo "    This does not prevent Cerberus from running."
fi

echo

# ------------------------------------------------------------
# Final validation
# ------------------------------------------------------------

echo "[*] Performing installation validation..."

if [[ ! -x "$LAUNCHER_PATH" ]]; then
    echo "[!] Launcher validation failed."
    exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[!] Configuration validation failed."
    exit 1
fi

if [[ ! -f "$PROJECT_DIR/cerberus/cli.py" ]]; then
    echo "[!] Cerberus CLI module was not found."
    exit 1
fi

echo "[+] Launcher:       OK"
echo "[+] Configuration:  OK"
echo "[+] Python source:   OK"
echo "[+] Dependencies:    OK"

echo
echo "=============================================================="
echo "                 CERBERUS INSTALLATION COMPLETE"
echo "=============================================================="
echo
echo "Run Cerberus with:"
echo
echo "    cerberus"
echo
echo "If this terminal cannot find the command yet, run:"
echo
echo "    source ~/.zshrc"
echo
