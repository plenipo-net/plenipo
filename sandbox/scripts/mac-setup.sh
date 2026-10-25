#!/usr/bin/env bash
# Plenipo sandbox setup for macOS (also works on Linux). Checks Node 22+, installs the library and the
# sandbox, builds the MCP bridge, and prints the configuration for Claude Desktop and Claude Code.
#
#   bash sandbox/scripts/mac-setup.sh
#
# Written for the bash 3.2 that ships with macOS.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sandbox="$(cd "$here/.." && pwd)"
root="$(cd "$sandbox/.." && pwd)"

say() { printf '\n\033[1m%s\033[0m\n' "$1"; }

say "1/4 Node.js"
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is not installed. Install Node 22 with Homebrew:"
  echo "  brew install node@22 && brew link --overwrite node@22"
  echo "(or from https://nodejs.org), then run this script again."
  exit 1
fi
version="$(node -v)"
major="${version#v}"; major="${major%%.*}"
if [ "$major" -lt 22 ]; then
  echo "Found Node $version; the sandbox needs Node 22 or later. With Homebrew:"
  echo "  brew install node@22 && brew link --overwrite node@22"
  exit 1
fi
node_bin="$(command -v node)"
echo "Node $version at $node_bin"

say "2/4 Library (npm ci in $root)"
(cd "$root" && npm ci --no-audit --no-fund)

say "3/4 Sandbox (npm ci in $sandbox)"
(cd "$sandbox" && npm ci --no-audit --no-fund)

say "4/4 MCP bridge (npm run build:bridge)"
(cd "$sandbox" && npm run build:bridge --silent)
bridge="$sandbox/dist/bridge.js"
echo "Built $bridge"

# Our ports, and whether something already listens on them (AirPlay Receiver takes 5000 and 7000, not these).
if command -v lsof >/dev/null 2>&1; then
  busy=""
  for p in 4400 4401 4402 4403 4404; do
    if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then busy="$busy $p"; fi
  done
  if [ -n "$busy" ]; then
    echo
    echo "Note: ports$busy are in use. Stop what uses them, or start the sandbox with SANDBOX_PORT_BASE=5400"
    echo "and set PLENIPO_PLATFORM_URL / PLENIPO_BANK_URL / PLENIPO_DASHBOARD_URL in the bridge config to match."
  fi
fi

say "Claude Desktop"
config="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
echo "Add this server to $config"
echo "(Claude menu > Settings... > Developer > Edit Config), then quit and reopen Claude Desktop:"
cat <<JSON

{
  "mcpServers": {
    "plenipo-bank": {
      "command": "$node_bin",
      "args": ["$bridge"],
      "env": {
        "PLENIPO_PLATFORM_URL": "http://127.0.0.1:4403",
        "PLENIPO_BANK_URL": "http://127.0.0.1:4404",
        "PLENIPO_DASHBOARD_URL": "http://127.0.0.1:4400"
      }
    }
  }
}
JSON
echo
echo "If the file already has an \"mcpServers\" object, add only the \"plenipo-bank\" entry to it."

say "Claude Code"
echo "  claude mcp add --transport stdio plenipo-bank -- \"$node_bin\" \"$bridge\""
echo "  claude mcp list        # should show plenipo-bank: Connected (once the sandbox runs)"

say "Next"
echo "  cd \"$sandbox\" && npm test          # the sandbox suite"
echo "  cd \"$sandbox\" && npm run sandbox   # then open http://127.0.0.1:4400"
echo "  Guide: $root/docs/mac.md"
