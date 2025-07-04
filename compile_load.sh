#!/usr/bin/env sh

TARGET="$1"
make && {
	if lsmod | grep -q "watchpoint" ; then
		sudo rmmod watchpoint
	fi
	sudo cp src/watchpoint.ko ${TARGET:-"/lib/modules/$(uname -r)/extra/"}
	sudo depmod
	sudo modprobe watchpoint

	if lsmod | grep -q "watchpoint" ; then
		echo -e "\033[1;34m MODULE LOADED \033[0m"
	fi
}
