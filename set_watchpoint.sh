#!/usr/bin/env sh

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <index> <address>"
    echo "Example: $0 1 0xdeadbeef"
    exit 1
fi

INDEX=$1
ADDR=$2
ATTR_PATH="/sys/kernel/watchpoint/watch_$INDEX"

echo "$ADDR" | sudo tee "$ATTR_PATH" > /dev/null

echo -e "Set watchpoint $INDEX to $ADDR: $(ls "${ATTR_PATH}") $(cat "${ATTR_PATH}")"
