#!/bin/bash

MINE=./ft_ssl
THEIR=openssl

test_digest() {
	mine="$(cat "$1" | $MINE "$2" | cut -d ' ' -f 2)"
	their="$(cat "$1" | $THEIR "$2" | cut -d ' ' -f 2)"

	if [ $mine != $their ]; then
		printf "$1" > fail
		echo "KO"
		echo "MINE:  $mine"
		echo "THEIR: $their"
		exit 1
	else
		echo "OK"
	fi
}

test_loop() {
	while true; do
		FILE="test_$1.txt"
		cat /dev/random | head -c $RANDOM > "$FILE"
		test_digest "$FILE" "$1"
	done
}

test_loop md5 &
test_loop sha256 &

wait
