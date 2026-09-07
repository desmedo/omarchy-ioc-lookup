#!/usr/bin/env bash
set -e

PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="$HOME/.config/omarchy/plugins/desmedo.ioc-lookup"
BIN_DIR="$HOME/.local/bin"
BINDINGS_FILE="$HOME/.config/hypr/bindings.lua"

KEYBIND="SUPER + ALT + I"
TOGGLE_CMD="omarchy-shell desmedo.ioc-lookup toggle"
BEGIN_MARK="-- BEGIN desmedo.ioc-lookup"
END_MARK="-- END desmedo.ioc-lookup"

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

# Keybinding. The overlay is only reachable over IPC, so without this the
# documented SUPER+ALT+I does nothing. Written into a marker block so
# re-running the installer replaces it instead of appending a duplicate.
install_keybinding() {
  if [[ ! -f "$BINDINGS_FILE" ]]; then
    echo "⚠️  $BINDINGS_FILE not found — skipping keybinding install."
    echo "    Add it manually:"
    echo "      o.bind(\"$KEYBIND\", \"IOCs Lookup\", \"$TOGGLE_CMD\")"
    return
  fi

  cp "$BINDINGS_FILE" "$BINDINGS_FILE.bak.$(date +%s)"
  sed -i "/^-- BEGIN desmedo\.ioc-lookup$/,/^-- END desmedo\.ioc-lookup$/d" "$BINDINGS_FILE"

  cat >>"$BINDINGS_FILE" <<EOF

$BEGIN_MARK
hl.unbind("$KEYBIND")
o.bind("$KEYBIND", "IOCs Lookup", "$TOGGLE_CMD")
$END_MARK
EOF

  echo "✅ Bound $KEYBIND in $BINDINGS_FILE"

  if command -v hyprctl >/dev/null 2>&1 && [[ -n ${HYPRLAND_INSTANCE_SIGNATURE:-} ]]; then
    hyprctl reload >/dev/null 2>&1 || true
    if hyprctl configerrors 2>/dev/null | grep -q .; then
      echo "⚠️  Hyprland reported config errors — run 'hyprctl configerrors'"
    fi
  fi
}

install_keybinding

echo "✅ Ready! Use $KEYBIND to open the overlay, or 'ioc <target>' in a terminal."
