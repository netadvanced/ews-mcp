#!/bin/sh
# Ensures ewsmcp always runs with this repo as cwd, so its .env auto-loads
# regardless of what directory the MCP client spawns it from.
cd "$(dirname "$0")" || exit 1
exec .venv/bin/ewsmcp
