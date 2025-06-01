#!/bin/bash

# Authorize more tokens in Zed editor
# This script uses AppleScript to automatically click the authorization button

echo "🔑 Attempting to authorize more tokens in Zed..."

# Run the AppleScript
result=$(osascript authorize_tokens.applescript 2>&1)

if [ $? -eq 0 ]; then
    echo "✅ Success: $result"
else
    echo "❌ Failed to authorize tokens"
    echo "Error: $result"
    echo ""
    echo "You may need to manually click the authorization button in Zed"
fi

# Make this script executable if it isn't already
if [ ! -x "$0" ]; then
    chmod +x "$0"
fi