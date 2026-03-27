#!/bin/bash
# Creates a new target workspace from template

if [ -z "$1" ]; then
    echo "Usage: ./new-target.sh <target-name>"
    echo "Example: ./new-target.sh shopify"
    exit 1
fi

TARGET_NAME="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
TARGET_DIR="$BASE_DIR/targets/$TARGET_NAME"
TEMPLATE_DIR="$BASE_DIR/targets/_template"

if [ -d "$TARGET_DIR" ]; then
    echo "Error: Target '$TARGET_NAME' already exists at $TARGET_DIR"
    exit 1
fi

cp -r "$TEMPLATE_DIR" "$TARGET_DIR"

# Replace placeholder with target name
sed -i "s/\[TARGET NAME\]/$TARGET_NAME/g" "$TARGET_DIR"/*.md

# Set today's date
TODAY=$(date +%Y-%m-%d)
sed -i "s/YYYY-MM-DD/$TODAY/g" "$TARGET_DIR/scope.md"

echo "Created target workspace: $TARGET_DIR"
echo "Next steps:"
echo "  1. Fill in scope.md with program details"
echo "  2. Run recon: ../recon/scripts/recon-runner.sh <domain>"
echo "  3. Start hunting!"
