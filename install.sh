#!/usr/bin/env bash
set -e

PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="$HOME/.config/omarchy/plugins/desmedo.ioc-lookup"
BIN_DIR="$HOME/.local/bin"

echo "🛡️ Installing Omarchy IOCs Lookup Suite..."

# Copy CLI binary
mkdir -p "$BIN_DIR"
cp "$PLUGIN_DIR/bin/ioc" "$BIN_DIR/ioc"
chmod +x "$BIN_DIR/ioc" "$PLUGIN_DIR/scripts/lookup.py"

# Example config
if [[ ! -f "$HOME/.config/omarchy/ioc-lookup.json" ]]; then
  cp "$PLUGIN_DIR/ioc-lookup.example.json" "$HOME/.config/omarchy/ioc-lookup.json"
fi

echo "✅ Installed CLI to $BIN_DIR/ioc"
echo "✅ Ready! Use SUPER+ALT+I to open overlay or 'ioc <target>' in terminal."
