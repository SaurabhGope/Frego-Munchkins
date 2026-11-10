#!/bin/sh
# Downloads the IEEE MA-L vendor registry (oui.csv) into the data directory, so identity
# can show vendor names. The daemon itself never downloads anything (DESIGN ADR-009).
set -eu
if [ -n "${FREGO_HOME:-}" ]; then
  dest="$FREGO_HOME"
elif [ "$(uname)" = "Darwin" ]; then
  dest="$HOME/Library/Application Support/FregoMunchkin"
else
  dest="${XDG_DATA_HOME:-$HOME/.local/share}/fregomunchkin"
fi
mkdir -p "$dest"
echo "Downloading the IEEE OUI registry to $dest/oui.csv"
curl -fsSL --retry 2 -A "FregoMunchkin/0.1 (local data fetch)" \
  -o "$dest/oui.csv.tmp" https://standards-oui.ieee.org/oui/oui.csv
mv "$dest/oui.csv.tmp" "$dest/oui.csv"
echo "Done: $(wc -l < "$dest/oui.csv") lines. Restart fregod to load it."
