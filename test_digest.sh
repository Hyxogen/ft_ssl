#!/bin/bash

MINE=./ft_ssl
THEIR=openssl

if [ -z "$1" ]; then
	echo "usage $0 <digest>"
	exit 0
fi

test_digest() {
	mine="$(cat "$1" | $MINE "$2" | cut -d ' ' -f 2)"
	their="$(cat "$1" | $THEIR "$2" | cut -d ' ' -f 2)"

	if [ $mine != $their ]; then
		cat "$1" > "fail_$2"
		echo "KO $2"
		echo "MINE:  $mine"
		echo "THEIR: $their"
		exit 1
	fi
}

while true; do
	FILE="/tmp/test_$1.txt"
	cat /dev/random | head -c $RANDOM > "$FILE"
	test_digest "$FILE" "$1"
done
