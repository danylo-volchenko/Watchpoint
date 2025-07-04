#!/usr/bin/env sh

if [ "$#" -lt 1 ]; then
	echo "Usage: $0 <address>"
	exit -22
fi
echo "$1" | sudo tee /sys/kernel/watchpoint/watch_address
