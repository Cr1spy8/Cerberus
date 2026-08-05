#!/usr/bin/env bash

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER_DIR="$HOME/bin"
LAUNCHER_PATH="$LAUNCHER_DIR/cerberus"

echo "=============================================="
echo "              CERBERUS INSTALLER"
echo "=============================================="
echo

if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] Python 3 is required but was not found."
    exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
    echo "[!] Nmap is required but was not found."
    echo "    Install with: sudo apt install nmap"
    exit 1
fi

mkdir -p "$LAUNCHER_DIR"

cat > "$LAUNCHER_PATH" <<EOF
#!/usr/bin/env bash

cd "$PROJECT_DIR" || exit 1
exec python3 -m cerberus.cli "\$@"
EOF

chmod +x "$LAUNCHER_PATH"

if [[ ":$PATH:" != *":$LAUNCHER_DIR:"* ]]; then
    SHELL_CONFIG="$HOME/.zshrc"

    if [[ ! -f "$SHELL_CONFIG" ]]; then
        SHELL_CONFIG="$HOME/.bashrc"
    fi

    if ! grep -Fq 'export PATH="$HOME/bin:$PATH"' "$SHELL_CONFIG"; then
        echo 'export PATH="$HOME/bin:$PATH"' >> "$SHELL_CONFIG"
    fi

    echo "[*] Added ~/bin to PATH in $SHELL_CONFIG"
    echo "[*] Restart the terminal or reload the shell configuration."
fi

echo
echo "[+] Cerberus launcher installed:"
echo "    $LAUNCHER_PATH"
echo
echo "[+] Run Cerberus with:"
echo "    cerberus"
